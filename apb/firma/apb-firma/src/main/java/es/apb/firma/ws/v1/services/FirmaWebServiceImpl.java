package es.apb.firma.ws.v1.services;
 
import javax.annotation.Resource;
import javax.jws.WebService;

import es.apb.firma.ws.exception.WException;
import es.apb.firma.ws.v1.model.PeticionFirmar;
import es.apb.firma.ws.v1.model.PeticionObtenerInfoCertificado;
import es.apb.firma.ws.v1.model.PeticionValidar;
import es.apb.firma.ws.v1.model.RespuestaFirmar;
import es.apb.firma.ws.v1.model.RespuestaObtenerInfoCertificado;
import es.apb.firma.ws.v1.model.RespuestaValidar;

/**
 * 
 * Servicio web que permite realizar diversas acciones de firma.
 * 
 * @author Indra
 * 
 */
@WebService(serviceName = "FirmarService_v1_00", endpointInterface = "es.apb.firma.ws.v1.services.FirmaWebService", targetNamespace = "urn:es:apb:firma:ws:v1:firma")
public final class FirmaWebServiceImpl implements FirmaWebService {

    /**
     * Controlador webservice.
     */
    @Resource(name = "firmaWebServiceCtrl")
    private FirmaWebService firmarWebServiceCtrl;


    @Override
    public RespuestaFirmar firmar(final PeticionFirmar peticion) throws WException {
        return firmarWebServiceCtrl.firmar(peticion);
    }

    @Override
    public RespuestaValidar validar(final PeticionValidar peticion) throws WException {
        return firmarWebServiceCtrl.validar(peticion);
    }

	@Override
	public RespuestaObtenerInfoCertificado obtenerInfoCertificado(
			final PeticionObtenerInfoCertificado peticion) throws WException {
		 return firmarWebServiceCtrl.obtenerInfoCertificado(peticion);
	}   
	
}
