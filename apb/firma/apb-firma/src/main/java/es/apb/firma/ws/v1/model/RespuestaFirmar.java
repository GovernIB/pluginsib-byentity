package es.apb.firma.ws.v1.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * Respuesta firma.
 * 
 * @author indra
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
public final class RespuestaFirmar {

    /**
     * Descripcion del error si ha surgido alguno.
     * 
     */
    @XmlElement(required = false)
    private byte[] firma;

    /**
     * Formato de la firma.
     * 
     */
    @XmlElement(required = true)
    private FormatoFirma formato;

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
     * Certificado en Base64.
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
     * @return the firma
     */
    public byte[] getFirma() {
        return firma;
    }

    /**
     * @param firma
     *            the firma to set
     */
    public void setFirma(final byte[] firma) {
        this.firma = firma;
    }

    /**
     * @return the formato
     */
    public FormatoFirma getFormato() {
        return formato;
    }

    /**
     * @param formato
     *            the formato to set
     */
    public void setFormato(final FormatoFirma formato) {
        this.formato = formato;
    }

    /**
     * @return the nif
     */
    public String getNif() {
        return nif;
    }

    /**
     * @param nif
     *            the nif to set
     */
    public void setNif(final String nif) {
        this.nif = nif;
    }

    /**
     * @return the nombreApellidos
     */
    public String getNombreApellidos() {
        return nombreApellidos;
    }

    /**
     * @param nombreApellidos
     *            the nombreApellidos to set
     */
    public void setNombreApellidos(final String nombreApellidos) {
        this.nombreApellidos = nombreApellidos;
    }

    /**
     * @return the certificadoB64
     */
    public String getCertificadoB64() {
        return certificadoB64;
    }

    /**
     * @param certificadoB64
     *            the certificadoB64 to set
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
     * @param pNifRepresentante
     *            the nifRepresentante to set
     */
    public void setNifRepresentante(final String pNifRepresentante) {
        nifRepresentante = pNifRepresentante;
    }

    /**
     * @return the nombreApellidosRepresentante
     */
    public String getNombreApellidosRepresentante() {
        return nombreApellidosRepresentante;
    }

    /**
     * @param pNombreApellidosRepresentante
     *            the nombreApellidosRepresentante to set
     */
    public void setNombreApellidosRepresentante(
            final String pNombreApellidosRepresentante) {
        nombreApellidosRepresentante = pNombreApellidosRepresentante;
    }

}
