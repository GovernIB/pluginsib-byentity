package es.apb.firma.ws.model;

/**
 * Datos certificado.
 * 
 * @author Indra
 */
public final class DatosCertificado {

    private String certificateB64;

    private String nif;

    private String nombreApellidos;

    private String nifRepresentante;

    private String nombreApellidosRepresentante;

    /**
     * @return the certificateB64
     */
    public String getCertificateB64() {
        return certificateB64;
    }

    /**
     * @param pCertificateB64
     *            the certificateB64 to set
     */
    public void setCertificateB64(final String pCertificateB64) {
        certificateB64 = pCertificateB64;
    }

    /**
     * @return the nif
     */
    public String getNif() {
        return nif;
    }

    /**
     * @param pNif
     *            the nif to set
     */
    public void setNif(final String pNif) {
        nif = pNif;
    }

    /**
     * @return the nombreApellidos
     */
    public String getNombreApellidos() {
        return nombreApellidos;
    }

    /**
     * @param pNombreApellidos
     *            the nombreApellidos to set
     */
    public void setNombreApellidos(final String pNombreApellidos) {
        nombreApellidos = pNombreApellidos;
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
