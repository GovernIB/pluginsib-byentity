package es.apb.firma.ws.exception;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.ws.WebFault;

import es.apb.firma.ws.model.ErrorFirmaWs;
 
/** 
 * Excepcion general para la capa de servicios web.
 * 
 * @author Indra
 * 
 */
@WebFault(name = "ExcepcionWS")
@XmlAccessorType(XmlAccessType.FIELD)
@SuppressWarnings("serial")
public final class WException extends RuntimeException {

    /**
     * Codigo error.
     */
    private final String codigoError;

    /**
     * Descripcion generica error.
     */
    private final String mensajeError;

    /**
     * Detalle error.
     */
    private final String detalleError;

    /**
     * Propiedades error.
     */
    private final WPropiedadesError propiedadesError;

    /**
     * Constructor que obliga a meter codigo error y detalle error.
     * 
     * @param pcodigoError
     *            codigo error
     * @param pmensajeError
     *            mensaje error
     * @param pdetalleError
     *            detalle error
     * @param ppropiedadesError
     *            propiedades error
     * @param cause
     *            excepcion original
     */
    public WException(final ErrorFirmaWs pcodigoError, final String pmensajeError,
            final String pdetalleError,
            final WPropiedadesError ppropiedadesError, final Throwable cause) {
        super(pcodigoError.name(), cause);
        codigoError = pcodigoError.name();
        detalleError = pdetalleError;
        mensajeError = pmensajeError;
        propiedadesError = ppropiedadesError;
    }

    /**
     * Obtiene el atributo codigo error de WException.
     *
     * @return the codigoError
     */
    public String getCodigoError() {
        return codigoError;
    }

    /**
     * Obtiene el atributo detalle error de WException.
     *
     * @return the detalleError
     */
    public String getDetalleError() {
        return detalleError;
    }

    /**
     * Obtiene el atributo mensaje error de WException.
     *
     * @return the mensajeError
     */
    public String getMensajeError() {
        return mensajeError;
    }

    /**
     * Obtiene el atributo propiedades error de WException.
     *
     * @return the propiedadesError
     */
    public WPropiedadesError getPropiedadesError() {
        return propiedadesError;
    }

}
