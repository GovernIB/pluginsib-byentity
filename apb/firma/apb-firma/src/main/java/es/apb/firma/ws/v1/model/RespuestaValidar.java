package es.apb.firma.ws.v1.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * RespuestaGestionPersistencia.
 * 
 * @author indra
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
public final class RespuestaValidar {
    /**
     * Resultado de la operacion.
     * 
     */
    @XmlElement(required = true)
    private boolean resultado;

    /**
     * Descripcion del error si ha surgido alguno.
     * 
     */
    @XmlElement(required = false)
    private String descripcionError;

    /**
     * Nif firmante.
     * 
     */
    @XmlElement(required = false)
    private String nif;

    /**
     * Nombre apellidos firmante.
     * 
     */
    @XmlElement(required = false)
    private String nombreApellidos;

    /**
     * Nif representante.
     * 
     */
    @XmlElement(required = false)
    private String nifRepresentante;

    /**
     * Nombre apellidos firmante.
     * 
     */
    @XmlElement(required = false)
    private String nombreApellidosRepresentante;

    /**
     * Certificado en Base64.
     * 
     */
    @XmlElement(required = false)
    private String certificadoB64;

    /**
     * @return the resultado
     */
    public boolean isResultado() {
        return resultado;
    }

    /**
     * @param iResultado
     *            the resultado to set
     */
    public void setResultado(final boolean iResultado) {
        this.resultado = iResultado;
    }

    /**
     * @return the descripcionError
     */
    public String getDescripcionError() {
        return descripcionError;
    }

    /**
     * @param iDescripcionError
     *            the descripcionError to set
     */
    public void setDescripcionError(final String iDescripcionError) {
        this.descripcionError = iDescripcionError;
    }

    /**
     * @return the nif
     */
    public String getNif() {
        return nif;
    }

    /**
     * @param iNif
     *            the nif to set
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
     * @param iNombreApellidos
     *            the nombreApellidos to set
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
