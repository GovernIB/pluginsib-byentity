package es.apb.firma.ws.exception;
import java.util.ArrayList;
import java.util.List;

/**
 * Lista de propiedades de un error.
 * 
 * @author Indra
 * 
 */
public final class WPropiedadesError {

    /**
     * Propiedades error.
     */
    private List<WPropiedadError> propiedadError = new ArrayList<WPropiedadError>();

    /**
     * Obtiene el atributo propiedad error de WPropiedadesError.
     *
     * @return the propiedadError
     */
    public List<WPropiedadError> getPropiedadError() {
        return propiedadError;
    }

    /**
     * Asigna el atributo propiedad error de WPropiedadesError.
     *
     * @param ppropiedadError the propiedadError to set
     */
    public void setPropiedadError(final List<WPropiedadError> ppropiedadError) {
        this.propiedadError = ppropiedadError;
    }

    /**
     * Añade propiedad .
     * 
     * @param wpe
     *            Propiedad
     * 
     */
    public void add(final WPropiedadError wpe) {
        propiedadError.add(wpe);
    }

    /**
     * Obtiene propiedades.
     * 
     * @return Propiedades
     */
    public List<WPropiedadError> get() {
        return propiedadError;
    }

}
