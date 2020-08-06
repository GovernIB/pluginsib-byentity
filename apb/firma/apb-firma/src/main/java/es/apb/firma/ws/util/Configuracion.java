package es.apb.firma.ws.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import es.apb.firma.ws.exception.WException;
import es.apb.firma.ws.model.ErrorFirmaWs;

/**
 * Clase para la configuración.
 *
 * @author slromero
 *
 */
public final class Configuracion {
	/** String certificate. */
	private static final String STRING_CERTIFICATE = "certificate.";

	/**
	 * Singleton.
	 */
	private static Configuracion conf;

	/** Propiedades. **/
	private Properties properties;

	/**
	 * Constructor.
	 */
	private Configuracion() {
	}

	/**
	 * Obtiene configuracion.
	 *
	 * @return Configuracion
	 * @throws IOException
	 *                         ioexception.
	 */
	public static Configuracion getInstance() {
		try {
			if (conf == null) {
				conf = new Configuracion();

				// Lee fichero configuracion
				InputStream is = null;
				Properties props = null;
				try {
					props = new Properties();
					// is =
					// Configuracion.class.getClassLoader().getResourceAsStream("configuracion.properties");
					is = new FileInputStream(System.getProperty("appConfPath") + "/apbfirma/configuracion.properties");
					props.load(is);

					conf.properties = props;

				} finally {
					if (is != null) {
						is.close();
					}
				}
			}
			return conf;
		} catch (final IOException ex) {
			throw new WException(ErrorFirmaWs.ERROR_CONFIGURACION, "Error al acceder a la configuracion",
					ex.getMessage(), null, ex);
		}
	}

	/**
	 * @param aliasCertificate
	 *                             aliasCertificate
	 * @return the keystorename
	 */
	public String getKeystoreName(final String aliasCertificate) {
		return properties.getProperty(STRING_CERTIFICATE + aliasCertificate + ".keystore");
	}

	/**
	 * @param aliasCertificate
	 *                             aliasCertificate
	 * @return the algorithm
	 */
	public String getAlgorithm(final String aliasCertificate) {
		return properties.getProperty(STRING_CERTIFICATE + aliasCertificate + ".algorithm");
	}

	/**
	 * @param aliasCertificate
	 *                             aliasCertificate
	 * @return the passwordKey
	 */
	public String getPasswordKey(final String aliasCertificate) {
		return properties.getProperty(STRING_CERTIFICATE + aliasCertificate + ".passwordKey");
	}

	/**
	 * @param aliasCertificate
	 *                             aliasCertificate
	 * @return the alias
	 */
	public String getAlias(final String aliasCertificate) {
		return properties.getProperty(STRING_CERTIFICATE + aliasCertificate + ".alias");
	}

	/**
	 * @param aliasCertificate
	 *                             aliasCertificate
	 * @return the passwordAlias
	 */
	public String getPasswordAlias(final String aliasCertificate) {
		return properties.getProperty(STRING_CERTIFICATE + aliasCertificate + ".passwordAlias");
	}

	/**
	 * @return the pathCertificados
	 */
	public String getPathCertificados() {
		return properties.getProperty("pathCertificates");
	}

	/**
	 * @return the applicationName
	 */
	public String getApplicationName() {
		return properties.getProperty("aplicationName");
	}

	/**
	 * @return the default certificate
	 */
	public String getDefaultCertificate() {
		return properties.getProperty("default.certificate");
	}

	/**
	 * @return the default format
	 */
	public String getDefaultFormat() {
		return properties.getProperty("default.format");
	}

	/**
	 * Security enabled.
	 *
	 * @return security enabled.
	 */
	public boolean isSecurityEnabled() {
		return "true".equals(properties.getProperty("security.enabled"));
	}

	/**
	 * User (Security enabled).
	 *
	 * @return user.
	 */
	public String getUser() {
		return properties.getProperty("security.user");
	}

	/**
	 * Password (Security enabled).
	 *
	 * @return user.
	 */
	public String getPassword() {
		return properties.getProperty("security.password");
	}

	/**
	 * Devuelve si se debugea validacion firma.
	 *
	 * @return boolean
	 */
	public boolean isDebugValidacionFirmas() {
		return "true".equals(properties.getProperty("debug.validacionFirma"));
	}

	/**
	 * Devuelve directorio donde se dejaran ficheros de validacion firma.
	 *
	 * @return user.
	 */
	public String getDirectorioDebugValidacionFirmas() {
		return properties.getProperty("debug.directorioTemporal");
	}

	/**
	 * @return the properties
	 */
	public Properties getProperties() {
		return properties;
	}

}
