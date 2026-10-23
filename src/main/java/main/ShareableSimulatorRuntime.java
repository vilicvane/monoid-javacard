package main;

import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.base.TransientMemory;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import javacard.framework.AID;
import javacard.framework.Shareable;

/** Adds SIO context switches missing from jCardSim, without emulating the firewall. */
public class ShareableSimulatorRuntime extends SimulatorRuntime {

  private final Map<Object, Shareable> proxies = new IdentityHashMap<>();
  private final Map<Object, Object> targets = new IdentityHashMap<>();
  private final Map<Object, AID> owners = new IdentityHashMap<>();

  public ShareableSimulatorRuntime() {}

  public ShareableSimulatorRuntime(TransientMemory memory) {
    super(memory);
  }

  @Override
  public byte[] transmitCommand(byte[] command) {
    try {
      return super.transmitCommand(command);
    } finally {
      // jCardSim leaves transactions active after process exits. Model the JCRE's
      // APDU boundary only; its abort still has no persistent-state rollback journal.
      if (getTransactionDepth() != 0) {
        abortTransaction();
      }
    }
  }

  @Override
  public Shareable getSharedObject(AID serverAID, byte parameter) {
    activateSimulatorRuntimeInstance();

    ApplicationInstance server = lookupApplet(serverAID);

    if (server == null) {
      return null;
    }

    AID caller = currentAID;
    AID previous = previousAID;
    AID owner = server.getAID();

    enterContext(owner);

    try {
      Shareable shared = server.getApplet().getShareableInterfaceObject(caller, parameter);
      return (Shareable) wrap(shared, owner);
    } finally {
      currentAID = caller;
      previousAID = previous;
    }
  }

  private Object wrap(Object value, AID owner) {
    if (value instanceof Object[]) {
      Object[] values = ((Object[]) value).clone();

      for (int index = 0; index < values.length; index++) {
        values[index] = wrap(values[index], owner);
      }

      return values;
    }

    if (!(value instanceof Shareable)) {
      return value;
    }

    Shareable existing = proxies.get(value);

    if (existing != null) {
      return existing;
    }

    Set<Class<?>> interfaces = new LinkedHashSet<>();

    for (Class<?> type = value.getClass(); type != null; type = type.getSuperclass()) {
      for (Class<?> contract : type.getInterfaces()) {
        if (Shareable.class.isAssignableFrom(contract)) {
          interfaces.add(contract);
        }
      }
    }

    Shareable proxy = (Shareable) Proxy.newProxyInstance(
      value.getClass().getClassLoader(),
      interfaces.toArray(new Class<?>[0]),
      (instance, method, arguments) -> invoke(value, owner, method, arguments)
    );

    proxies.put(value, proxy);
    proxies.put(proxy, proxy);
    targets.put(proxy, value);
    owners.put(proxy, owner);

    return proxy;
  }

  private Object invoke(Object target, AID owner, Method method, Object[] arguments)
    throws Throwable {
    activateSimulatorRuntimeInstance();

    AID caller = currentAID;
    AID previous = previousAID;
    arguments = (Object[]) wrap(arguments, caller);
    if (arguments != null) {
      for (int index = 0; index < arguments.length; index++) {
        AID argumentOwner = owners.get(arguments[index]);
        // Returning a SIO to its own context exposes the original object, not a new callback.
        if (argumentOwner != null && sameContext(owner, argumentOwner)) {
          arguments[index] = targets.get(arguments[index]);
        }
      }
    }

    enterContext(owner);

    try {
      return wrap(method.invoke(target, arguments), owner);
    } catch (InvocationTargetException exception) {
      throw exception.getCause();
    } finally {
      currentAID = caller;
      previousAID = previous;
    }
  }

  private void enterContext(AID owner) {
    // Applets in the same package share a context; their calls retain its caller.
    if (currentAID == null || !sameContext(currentAID, owner)) {
      previousAID = currentAID;
    }

    currentAID = owner;
  }

  private boolean sameContext(AID first, AID second) {
    return getApplet(first)
      .getClass()
      .getPackage()
      .equals(getApplet(second).getClass().getPackage());
  }
}
