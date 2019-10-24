package es.apb.sistra.loginmodule;

import java.security.Principal;
import java.security.acl.Group;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.naming.InitialContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;

import java.util.HashMap;

/**
 * Login module para clave basado en ticket.
 * 
 * 
 * Username={TICKET-sessionId} Password=ticket
 * 
 */
public class ClaveLoginIBModule extends UsernamePasswordLoginModule {

    /** Timeout ticket (segundos) */
    private long timeoutTicket;

    /** Purga ticket (minutos) */
    private int purgaTicket;
    
    /** 
     * Tiempo de guardado en memoria de tickets logados (segundos)
     */
    private long timeLoggedTicket;

    /**
     * Principal customizado
     */
    private ApbPrincipal caller;

    /**
     * Role de acceso publico
     */
    private String roleTothom;

    /**
     * URL LoginIB
     */
    private String loginIBURL;
    
    /**
     * Usuario de conexion a LoginIB
     */
    private String user;
    
    /**
     * Password del usuario de conexion a LoginIB
     */
    private String password;
    
	/** Tickets ya logados. **/
	private static final Map<String, TicketAutenticado> ticketsLogados = new HashMap<String, TicketAutenticado>();
	
    /** Endpoint servicio autenticacion . */
    private static final String ENDPOINT = "/ticket/";

    /**
     * Inicializacion
     */
    @Override
    public void initialize(final Subject subject,
            final CallbackHandler callbackHandler, final Map sharedState,
            final Map options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        roleTothom = (String) options.get("roleTothom");
        timeoutTicket = Long.parseLong((String) options.get("timeoutTicket"));
        purgaTicket = Integer.parseInt((String) options.get("purgaTicket"));
        timeLoggedTicket = Long.parseLong((String) options.get("timeLoggedTicket"));
        loginIBURL = (String) options.get("loginIBURL");
        user = (String) options.get("user");
        password = (String) options.get("password");
    }

    /**
     * Login
     */
    @Override
    public boolean login() throws LoginException {
        // Comprobamos si esta habilitado UseFirstPass
        if (getUseFirstPass() == true) {
            return super.login();
        } else {
            return loginCertificate();
        }
    }

    public boolean loginCertificate() throws LoginException {
        log.debug("enter: login()");
        super.loginOk = false;

        // Obtenemos usuario y password
        final String[] userPass = this.getUsernameAndPassword();
        final String username = userPass[0]; // Usuario: {TICKET-sessionId}
        final String ticketClave = userPass[1]; // Password: ticket
        if (username == null || !username.startsWith("{TICKET-")) {
            return false;
        }

        // Obtenemos sesion id
        final String sesionId = username.substring("{TICKET-".length(),
                username.length() - 1);

        // Creamos principal
        try {
            caller = obtenerInfoSesionAutenticacion(sesionId, ticketClave);
        } catch (final Exception e) {
            log.error("Error creando ApbPrincipal a partir ticket", e);
            throw new LoginException(
                    "Error creando ApbPrincipal a partir ticket");
        }

        // Establecemos shared state
        if (getUseFirstPass() == true) {
            // Add authentication info to shared state map
            sharedState.put("javax.security.auth.login.name", caller.getName());
            sharedState.put("javax.security.auth.login.password", ticketClave);
        }

        // Damos login por realizado
        super.loginOk = true;
        log.debug("Login OK para " + caller.getName());
        return true;

    }

    @Override
    protected Principal getIdentity() {
        Principal identity = caller;
        if (identity == null)
            identity = super.getIdentity();
        return identity;
    }

    /**
     * No utilizada se sobreescribe login
     */
    @Override
    protected String getUsersPassword() throws LoginException {
        return null;
    }

    /**
     * Obtiene roles usuario (modificado para que no llame a createIdentity al
     * crear cada role)
     */
    @Override
    protected Group[] getRoleSets() throws LoginException {
        final Principal principal = getIdentity();

        if (!(principal instanceof ApbPrincipal)) {
            if (log.isTraceEnabled())
                log.trace("Principal " + principal + " not a ApbPrincipal");
            return new Group[0];
        }

        final String username = getUsername();

        List roles = null;
        try {
            roles = getUserRoles(username);
        } catch (final Exception e) {
            log.error("Excepcion obteniendo roles", e);
            throw new LoginException("Excepcion obteniendo roles");
        }

        final Group rolesGroup = new SimpleGroup("Roles");
        for (final Iterator iterator = roles.iterator(); iterator.hasNext();) {
            final String roleName = (String) iterator.next();
            rolesGroup.addMember(new SimplePrincipal(roleName));
        }
        final HashMap setsMap = new HashMap();
        setsMap.put("Roles", rolesGroup);

        // Montamos grupo "CallerPrincipal"
        final Group principalGroup = new SimpleGroup("CallerPrincipal");
        principalGroup.addMember(principal);
        setsMap.put("CallerPrincipal", principalGroup);

        // Devolvemos respuesta
        final Group roleSets[] = new Group[setsMap.size()];
        setsMap.values().toArray(roleSets);
        return roleSets;
    }

    /**
     * Obtiene roles asociados al usuario. En este caso serán accesos por
     * ciudadanos que tendrán el role tothom
     * 
     * @param username
     * @return
     */
    private List getUserRoles(final String username) {
        final List userRoles = new ArrayList();
        userRoles.add(roleTothom);
        return userRoles;
    }

    private ApbPrincipal obtenerInfoSesionAutenticacion(
            final String sesionIdTicket, final String ticket) throws Exception {
    	
		final HttpClient client = new HttpClient();
		final String urlClave = loginIBURL + ENDPOINT + ticket;
		final GetMethod getMethod = new GetMethod(urlClave);
		
        try {
        	
        	Iterator it = ticketsLogados.keySet().iterator();
        	while(it.hasNext()){
        	  TicketAutenticado key = (TicketAutenticado) ticketsLogados.get(it.next());
        	  final boolean purgar = (System.currentTimeMillis()
                      - key.getFechaLogin().getTime() > (purgaTicket * 60000L));
        	  if(purgar){
        		  log.debug("Purgado de ticket " + ticket);
        		  ticketsLogados.remove(ticket);  
        	  }
        	  
        	}
        	
        	// Comprobamos si el tiquet ya ha sido utilizado
        	if (ticketsLogados.containsKey(ticket)) {
        		// Comprobamos si se ha superado el tiempo de caché
                // Controlar Timeout (si es el primer login)
        		final TicketAutenticado ticAut = ticketsLogados.get(ticket);
                final boolean timeout = (System.currentTimeMillis()
                            - ticAut.getFechaLogin().getTime() > (timeLoggedTicket * 1000L));

                if (timeout){
                	log.debug("Eliminamos tiquet " + ticket + " por timeout de uso");
                	ticketsLogados.remove(ticket);
                	throw new LoginException("El ticket ha caducado");
                }
                
                return ticAut.getPrincipalAut();        		
        		
        	}else{
        		
        		Map<String, String> exp = new HashMap<String, String>();
        		
			  	final String plainCreds = user + ":" + password;
		        final byte[] plainCredsBytes = plainCreds.getBytes();
		        final byte[] base64CredsBytes = Base64.encodeBase64(plainCredsBytes);
		        final String base64Creds = new String(base64CredsBytes);
        		

        		getMethod.addRequestHeader("Content-Type", "application/json");
        		getMethod.addRequestHeader("Authorization", "Basic " + base64Creds);
        		int status = client.executeMethod(getMethod);
        		
        	    if (status != HttpStatus.SC_OK) {
        	    	throw new LoginException(
                            "Error al invocar el servicio de obtención de datos de autenticación de LoginIB" + getMethod.getStatusText());
        	    }
        		
        		final String response = getMethod.getResponseBodyAsString();
        		
        		JSONObject datosAut = new JSONObject(response);
        		final String metAut = datosAut.get("metodoAutenticacion").toString();
        		final String nif = datosAut.get("nif").toString();
        		final String nombre = datosAut.get("nombre").toString();
        		final String apellidos = datosAut.get("apellidos").toString();
        		
        		String nombreCompleto = nombre + ' ' + apellidos;     		
        		
        		Representante r = null;
        		
        		if (datosAut.has("representante") && !JSONObject.NULL.equals(datosAut.get("representante"))){
        			JSONObject Rep = (JSONObject) datosAut.get("representante");
                    r = new Representante();
                    r.setNif(Rep.get("nif").toString());
                    r.setNombre(Rep.get("nombre").toString());
                    r.setApellido1(Rep.get("apellido1").toString());
                    r.setApellido2(Rep.get("apellido2").toString());        			
        		}
        		
                String metodoAutenticacion = "";
                
        		if ("ANONIMO".equals(metAut)) {
        			metodoAutenticacion = "A";
        		} else if ("CLAVE_CERTIFICADO".equals(metAut)){
        			metodoAutenticacion = "C";
        		} else if ("CLAVE_PIN".equals(metAut) || "CLAVE_PERMANENTE".equals(metAut)) {
        			metodoAutenticacion = "U";
        		}
        		
        		ApbPrincipal principal = new ApbPrincipal(nif, nombreCompleto, nif,
                        metodoAutenticacion.charAt(0), r);
        		
        		TicketAutenticado nuevoTicket = new TicketAutenticado();
        		nuevoTicket.setFechaLogin(new Date(System.currentTimeMillis()));
        		nuevoTicket.setPrincipalAut(principal);
        		
                ticketsLogados.put(ticket, nuevoTicket);
                
                return principal; 
        		
        	}

        } finally {
        	getMethod.releaseConnection();
        }
    }

    @Override
    protected Principal createIdentity(final String username) throws Exception {
        return super.createIdentity(username);
    }

}
