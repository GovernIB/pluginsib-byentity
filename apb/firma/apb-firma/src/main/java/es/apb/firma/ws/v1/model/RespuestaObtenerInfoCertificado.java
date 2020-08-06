package es.apb.firma.ws.v1.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * Respuesta obtener info certificado.
 *
 * @author indra
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
public final class RespuestaObtenerInfoCertificado {

	/**
	 * Descripcion del error si ha surgido alguno.
	 *
	 */
	@XmlElement(required = true)
	private String nif;

	/**
	 * Descripcion del error si ha surgido alguno.
	 *
	 */
	@XmlElement(required = true)
	private String nombreApellidos;

	/**
	 * Certificado en B64 (por si se ha obtenido la info a partir de la firma).
	 *
	 */
	@XmlElement(required = true)
	private String certificadoB64;

	/**
	 * Nif representante si el certificado es de representacion.
	 *
	 */
	@XmlElement(required = false)
	private String nifRepresentante;

	/**
	 * Nombre representante si el certificado es de representacion.
	 *
	 */
	@XmlElement(required = false)
	private String nombreApellidosRepresentante;

	/**
	 * @return the nif
	 */
	public String getNif() {
		return nif;
	}

	/**
	 * @param iNif the nif to set
	 */
	public void setNif(final String iNif) {
		this.nif = iNif;
	}

	/**
	 * @return the nombreApellidos
	 */
	public String getNombreApellidos() {
		return nombreApellidos;
	}

	/**
	 * @param iNombreApellidos the nombreApellidos to set
	 */
	public void setNombreApellidos(final String iNombreApellidos) {
		this.nombreApellidos = iNombreApellidos;
	}

	/**
	 * @return the certificadoB64
	 */
	public String getCertificadoB64() {
		return certificadoB64;
	}

	/**
	 * @param certificadoB64 the certificadoB64 to set
	 */
	public void setCertificadoB64(final String certificadoB64) {
		this.certificadoB64 = certificadoB64;
	}

	/**
	 * @return the nifRepresentante
	 */
	public String getNifRepresentante() {
		return nifRepresentante;
	}

	/**
	 * @param pNifRepresentante the nifRepresentante to set
	 */
	public void setNifRepresentante(final String pNifRepresentante) {
		nifRepresentante = pNifRepresentante;
	}

	/**
	 * @return the nombreRepresentante
	 */
	public String getNombreApellidosRepresentante() {
		return nombreApellidosRepresentante;
	}

	/**
	 * @param pNombreRepresentante the nombreRepresentante to set
	 */
	public void setNombreApellidosRepresentante(final String pNombreRepresentante) {
		nombreApellidosRepresentante = pNombreRepresentante;
	}
}
