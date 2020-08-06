package es.apb.firma.ws.exception;

/**
 * Detalle de una excepcion.
 * 
 * @author Indra
 * 
 */
public final class WPropiedadError {

    /**
     * Propiedad.
     */
    private String propiedad;

    /**
     * Valor.
     */
    private String valor;

    /**
     * Obtiene el atributo propiedad de WPropiedadError.
     * 
     * @return the propiedad
     */
    public String getPropiedad() {
        return propiedad;
    }

    /**
     * Asigna el atributo propiedad de WPropiedadError.
     * 
     * @param ppropiedad
     *            the propiedad to set
     */
    public void setPropiedad(final String ppropiedad) {
        this.propiedad = ppropiedad;
    }

    /**
     * Obtiene el atributo valor de WPropiedadError.
     * 
     * @return the valor
     */
    public String getValor() {
        return valor;
    }

    /**
     * Asigna el atributo valor de WPropiedadError.
     * 
     * @param pvalor
     *            the valor to set
     */
    public void setValor(final String pvalor) {
        this.valor = pvalor;
    }

    /**
     * Crea nueva instancia.
     * 
     * @return WPropiedadError
     */
    public static WPropiedadError createNewWPropiedadError() {
        return new WPropiedadError();
    }

}
