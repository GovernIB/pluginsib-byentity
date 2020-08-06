package es.apb.firma.ws.model;


import es.apb.firma.ws.exception.WException;
import es.apb.firma.ws.v1.services.FirmaWebService;



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
public final class RespuestaInfo {

    /** Resultado. **/
    private boolean resultado;

    /** Descripcion error. **/
    private String descripcionError;

    /** Certificado (base 64). */
    private String certificateB64;

    /** Nif. */
    private String nif;

    /** Nombre y apellidos. */
    private String nombreApellidos;

    /*******************
     * DATOS DE RESPUESTA DE @FIRMA
     ****************** 
     */
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
     * Método que se encarga de almacenar en nombreApellidos y nif los campos
     * obtenidos de @Firma, teniendo en cuenta dependerá de la clasificación de
     * la firma. Sólo es llamado desde el servicio web para obtener la info de
     * una firma.
     */
    public void prepararDatosObtenerInfoCertificado() {

        // Si está vacío el campo, se extrae de organización.
        if (clasificacion != null && "4".equals(clasificacion)) {
            // - Sello (4)
            this.nombreApellidos = organizacion;
            this.nif = nifEntidadSuscriptora;
        } else if (clasificacion != null
                && ("0".equals(clasificacion) || "5".equals(clasificacion))) {
            // - Persona fisica (0) / Empleado publico (5)
            this.nombreApellidos = nombreApellidosResponsable;
            this.nif = nifResponsable;
        } else if (clasificacion != null
                && ("1".equals(clasificacion) || "11".equals(clasificacion) || "12"
                        .equals(clasificacion))) {
            // - Persona juridica (1) / Representante Entidad (11) /
            // Representante Entidad sin personalidad juridica (12)
            this.nombreApellidos = razonSocial;
            this.nif = nifCif;
        } else {
            // Resto no soportados
            throw new WException(ErrorFirmaWs.ERROR_CERTIFICADO_NO_SOPORTADO,
            		"Certificado tipo " + clasificacion + " no soportado.", null, null, null);
        }

        // Si no están rellanos, lanzar error!
        if (this.nombreApellidos.isEmpty() || this.nif.isEmpty()) {
            throw new WException(
                    ErrorFirmaWs.ERROR_CERTIFICADO_DATOS_INCOMPLETOS,
                    "Los datos del certificado están incompletos.", null, null,
                    null);
        }
    }

}
