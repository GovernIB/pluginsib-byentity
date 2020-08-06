package es.apb.firma.ws.model;

/**
 * Informacion a recuperar de la respuesta de los servicios.
 * 
 * Como los servicios devuelven un Map de Maps, esta clase contiene los posibles
 * atributos de las diferentes respuestas. Depende del servicio se usaran unos
 * atributos u otros.
 * 
 * @author rsanz
 * 
 */
public final class RespuestaAFirma {

    /** Resultado. **/
    private boolean resultado;

    /** Descripcion error. **/
    private String descripcionError;
    /** Certificado (base 64). */
    private String certificateB64;
    /** Clasificación según @Firma. **/
    private String clasificacion;
    /** Nif responsable según @Firma. **/
    private String nifResponsable;
    /** Nombre y apellidos del responsable según @Firma. **/
    private String nombreApellidosResponsable;
    /** Nif Entidad Suscriptora según @Firma. **/
    private String nifEntidadSuscriptora;
    /** Organización según @Firma. **/
    private String organizacion;
    /** Razón social según @Firma. **/
    private String razonSocial;
    /** NifCif según @Firma. **/
    private String nifCif;

    public RespuestaAFirma() {
    }

    /**
     * @return the certificateB64
     */
    public String getCertificateB64() {
        return certificateB64;
    }

    /**
     * @param iCertificateB64
     *            the certificateB64 to set
     */
    public void setCertificateB64(final String iCertificateB64) {
        this.certificateB64 = iCertificateB64;
    }

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
     * @param iClasificacion
     *            the clasificacion to set
     */
    public void setClasificacion(final String iClasificacion) {
        this.clasificacion = iClasificacion;
    }

    /**
     * @param iNifResponsable
     *            the nifResponsable to set
     */
    public void setNifResponsable(final String iNifResponsable) {
        this.nifResponsable = iNifResponsable;
    }

    /**
     * @param iNombreApellidosResponsable
     *            the nombreApellidosResponsable to set
     */
    public void setNombreApellidosResponsable(
            final String iNombreApellidosResponsable) {
        this.nombreApellidosResponsable = iNombreApellidosResponsable;
    }

    /**
     * @param iNifEntidadSuscriptora
     *            the nifEntidadSuscriptora to set
     */
    public void setNifEntidadSuscriptora(final String iNifEntidadSuscriptora) {
        this.nifEntidadSuscriptora = iNifEntidadSuscriptora;
    }

    /**
     * @param iOrganizacion
     *            the organizacion to set
     */
    public void setOrganizacion(final String iOrganizacion) {
        this.organizacion = iOrganizacion;
    }

    /**
     * @param iRazonSocial
     *            the razonSocial to set
     */
    public void setRazonSocial(final String iRazonSocial) {
        this.razonSocial = iRazonSocial;
    }

    /**
     * @return the razonSocial
     */
    public String getRazonSocial() {
        return razonSocial;
    }

    /**
     * @param iNifCif
     *            the nifCif to set
     */
    public void setNifCif(final String iNifCif) {
        this.nifCif = iNifCif;
    }

    /**
     * @return the nifCif
     */
    public String getNifCif() {
        return nifCif;
    }

    /**
     * @return the clasificacion
     */
    public String getClasificacion() {
        return clasificacion;
    }

    /**
     * @return the nifResponsable
     */
    public String getNifResponsable() {
        return nifResponsable;
    }

    /**
     * @return the nombreApellidosResponsable
     */
    public String getNombreApellidosResponsable() {
        return nombreApellidosResponsable;
    }

    /**
     * @return the nifEntidadSuscriptora
     */
    public String getNifEntidadSuscriptora() {
        return nifEntidadSuscriptora;
    }

    /**
     * @return the organizacion
     */
    public String getOrganizacion() {
        return organizacion;
    }

}
