package es.apb.firma.ws.v1.services;
 
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.xml.ws.RequestWrapper;
import javax.xml.ws.ResponseWrapper;

import es.apb.firma.ws.exception.WException;
import es.apb.firma.ws.v1.model.PeticionFirmar;
import es.apb.firma.ws.v1.model.PeticionObtenerInfoCertificado;
import es.apb.firma.ws.v1.model.PeticionValidar;
import es.apb.firma.ws.v1.model.RespuestaFirmar;
import es.apb.firma.ws.v1.model.RespuestaObtenerInfoCertificado;
import es.apb.firma.ws.v1.model.RespuestaValidar;
/**
 * 
 * Servicio web que permite realizar diversas acciones de firma. Entre las opciones disponbiles:
 * <ul>
 *     <li>Firmar un documento.</li>
 *     <li>Certificar un certificado.</li>
 *     <li>Certificar un documento y comprobar que ha sido firmado por la misma persona. </li>
 * </ul>
 * 
 * @author Indra
 * 
 */ 
@WebService(targetNamespace = "urn:es:apb:firma:ws:v1:firma")
public interface FirmaWebService {

    /**
     * Método que firma un documento de entrada y devuelve la firma. 
     * @param peticion Petición con los datos a firmar.
     * @return Devuelve el contenido y resultado de firmar.
     * @throws WException Excepcion lanzada.
     */
     @WebMethod(operationName = "firmar")
     @RequestWrapper(localName = "firmarRequest")
     @ResponseWrapper(localName = "firmarResponse")
     @WebResult(name = "respuesta")
     RespuestaFirmar firmar(
              @WebParam(name = "peticion") PeticionFirmar peticion)
     throws WException;


     /**
      * Método que valida una firma respecto a un documento y devuelve nif/nombreCompleto.
      * @param peticion Petición con los datos a validar, tanto el documento como la firma.
      * @return Devuelve el contenido y resultado de firmar.
      * @throws WException Excepcion lanzada.   
      */
    @WebMethod(operationName = "validar")
    @RequestWrapper(localName = "validarRequest")
    @ResponseWrapper(localName = "validarResponse")
    @WebResult(name = "respuesta")
    RespuestaValidar validar(
                @WebParam(name = "peticion") PeticionValidar peticion)
    throws WException;

    
    /**
     * Método que obtiene info del certificado.
     * @param peticion Petición con el certificado en base 64.
     * @return Devuelve la info del certificado.
     * @throws WException Excepcion lanzada.    
     */
   @WebMethod(operationName = "obtenerInfoCertificado")
   @RequestWrapper(localName = "obtenerInfoCertificadoRequest")
   @ResponseWrapper(localName = "obtenerInfoCertificadoResponse")
   @WebResult(name = "respuesta")
   RespuestaObtenerInfoCertificado obtenerInfoCertificado(
               @WebParam(name = "peticion") PeticionObtenerInfoCertificado peticion)
   throws WException;
     
   
}
