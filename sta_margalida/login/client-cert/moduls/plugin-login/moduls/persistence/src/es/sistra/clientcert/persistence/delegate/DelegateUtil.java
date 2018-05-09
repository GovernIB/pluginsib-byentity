package es.sistra.clientcert.persistence.delegate;

/**
 * Define m�todos est�ticos para obtener delegates locales
 */
public final class DelegateUtil {

    private DelegateUtil() {

    }
  
    public static LoginDelegate getLoginDelegate() {
        return (LoginDelegate) DelegateFactory.getDelegate(LoginDelegate.class);
    }
    
    public static ConfiguracionDelegate getConfiguracionDelegate() {
        return (ConfiguracionDelegate) DelegateFactory.getDelegate(ConfiguracionDelegate.class);
    }
    
 }
