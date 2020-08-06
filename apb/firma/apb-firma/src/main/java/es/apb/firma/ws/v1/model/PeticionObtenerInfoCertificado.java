package es.apb.firma.ws.v1.model;
 
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * Peticion de obtener info certificado en base a una firma o a un certificado.
 * 
 * Se debe establecer un certificado o la firma (firma y formato).
 * 
 * @author indra
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
public final class PeticionObtenerInfoCertificado {

    /**
     * Certificado en B64.
     */
    @XmlElement(required = false)
    private String certificadoB64;
    
    /**
     * Firma.
     */
    @XmlElement(required = false)
    private byte[] contenidoFirma;
    
    /**
     * Firma.
     */
    @XmlElement(required = false)
    private FormatoFirma formatoFirma;

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
	 * @return the contenidoFirma
	 */
	public byte[] getContenidoFirma() {
		return contenidoFirma;
	}

	/**
	 * @param contenidoFirma the contenidoFirma to set
	 */
	public void setContenidoFirma(byte[] contenidoFirma) {
		this.contenidoFirma = contenidoFirma;
	}

	/**
	 * @return the formatoFirma
	 */
	public FormatoFirma getFormatoFirma() {
		return formatoFirma;
	}

	/**
	 * @param formatoFirma the formatoFirma to set
	 */
	public void setFormatoFirma(FormatoFirma formatoFirma) {
		this.formatoFirma = formatoFirma;
	}

   
}
