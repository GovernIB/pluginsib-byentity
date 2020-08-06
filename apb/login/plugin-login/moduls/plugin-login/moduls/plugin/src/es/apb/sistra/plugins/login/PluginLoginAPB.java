package es.apb.sistra.plugins.login;

import java.security.Principal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.naming.InitialContext;
import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.apb.sistra.loginmodule.ApbPrincipal;
import es.caib.sistra.plugins.login.EvidenciasAutenticacion;
import es.caib.sistra.plugins.login.PeticionInicioSesionAutenticacion;
import es.caib.sistra.plugins.login.PluginLoginIntf;

/**
 * Plugin Login APB.
 * 
 * @author rsanz
 * 
 */
public class PluginLoginAPB implements PluginLoginIntf {

    /** Log. */
    private static Log log = LogFactory.getLog(PluginLoginAPB.class);

    /**
     * Obtiene metodo de autenticacion
     */
    public char getMetodoAutenticacion(final Principal principal) {
        final ApbPrincipal mp = (ApbPrincipal) principal;
        return mp.getMetodoAutenticacion();
    }

    /**
     * Obtiene nif
     */
    public String getNif(final Principal principal) {
        final ApbPrincipal mp = (ApbPrincipal) principal;
        return mp.getNif();
    }

    /**
     * Obtiene nombre y apellidos
     */
    public String getNombreCompleto(final Principal principal) {
        final ApbPrincipal mp = (ApbPrincipal) principal;
        return mp.getNombreCompleto();
    }

    /**
     * Obtiene url destino de sesion de clave basada en ticket.
     * 
     * @param ticket
     *            Ticket
     * @return Url destino
     * @throws Exception
     */
    public String obtenerUrlDestinoSesionAutenticacion(final String ticket)
            throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            conn = getConnection();

            ps = conn
                    .prepareStatement("SELECT TCK_URLDST FROM ZPE_TICKET WHERE TCK_TICKET = ?");
            ps.setString(1, ticket);
            rs = ps.executeQuery();
            if (!rs.next()) {
                throw new Exception("No se encuentra informacion de sesion");
            }
            final String urlDestino = rs.getString("TCK_URLDST");
            return urlDestino;
        } finally {
            if (rs != null)
                try {
                    rs.close();
                } catch (final SQLException e) {
                }
            if (ps != null)
                try {
                    ps.close();
                } catch (final SQLException e) {
                }
            if (conn != null)
                try {
                    conn.close();
                } catch (final SQLException ex) {
                }
        }
    }

    /**
     * Obtiene contexto web autenticador clave.
     * 
     * @return contexto
     */
    public String obtenerContextoAutenticadorClave() throws Exception {
        return ConfigurationUtil.getInstance().obtenerPropiedades()
                .getProperty("contextAutenticadorClave");
    }
    
    /**
     * Obtiene usuario de conexión con los servicios de LoginIB
     * 
     * @return usuario
     */
    public String obtenerUsuarioLoginIB() throws Exception {
        return ConfigurationUtil.getInstance().obtenerPropiedades()
                .getProperty("usuarioLoginIB");
    }
    
    /**
     * Obtiene el password del usuario de conexión con los servicios de LoginIB
     * 
     * @return password
     */
    public String obtenerPasswordLoginIB() throws Exception {
        return ConfigurationUtil.getInstance().obtenerPropiedades()
                .getProperty("passwordLoginIB");
    }

    private Connection getConnection() throws Exception {
        Connection conn;
        final InitialContext ctx = new InitialContext();
        final DataSource ds = (DataSource) ctx.lookup(ConfigurationUtil
                .getInstance().obtenerPropiedades()
                .getProperty("datasourceTicketClave"));
        conn = ds.getConnection();
        return conn;
    }

    public String getRepresentanteApellido1(final Principal principal) {
        String res = null;
        final ApbPrincipal mp = (ApbPrincipal) principal;
        if (mp.getRepresentante() != null) {
            res = mp.getRepresentante().getApellido1();
        }
        return res;
    }

    public String getRepresentanteApellido2(final Principal principal) {
        String res = null;
        final ApbPrincipal mp = (ApbPrincipal) principal;
        if (mp.getRepresentante() != null) {
            res = mp.getRepresentante().getApellido2();
        }
        return res;
    }

    public String getRepresentanteNif(final Principal principal) {
        String res = null;
        final ApbPrincipal mp = (ApbPrincipal) principal;
        if (mp.getRepresentante() != null) {
            res = mp.getRepresentante().getNif();
        }
        return res;
    }

    public String getRepresentanteNombre(final Principal principal) {
        String res = null;
        final ApbPrincipal mp = (ApbPrincipal) principal;
        if (mp.getRepresentante() != null) {
            res = mp.getRepresentante().getNombre();
        }
        return res;
    }

	public EvidenciasAutenticacion getEvidenciasAutenticacion(
			String paramString) {
		return null;
	}

	public String getIdSesionAutenticacion(Principal paramPrincipal) {
		return null;
	}

	public String iniciarSesionAutenticacion(
			PeticionInicioSesionAutenticacion paramPeticionInicioSesion) {
		return null;
	}

}
