package es.apb.firma.ws.model;

/**
 * Errores de firma que se dan en el webservice.
 * @author rsanz
 *
 */
public enum ErrorFirmaWs {
    /** Error no controlado. **/
    ERROR_NO_CONTROLADO,
    /** Error accediendo configuracion. **/
    ERROR_CONFIGURACION,
    /** Error conexion afirma. **/
    ERROR_CONEXION_AFIRMA,
    /** Error transformacion XML. **/
    ERROR_TRANSFORMACION_XML,
    /** Error asociado a operacion firma y validacion. **/
    ERROR_FIRMA,
    /** Error certificado no soportado. **/
    ERROR_CERTIFICADO_NO_SOPORTADO,
    /** Error formato firma no soportado. **/
    ERROR_FORMATO_FIRMA_NO_SOPORTADO, 
    /** Error los datos del firmado están incompletos. **/
    ERROR_CERTIFICADO_DATOS_INCOMPLETOS;
}
