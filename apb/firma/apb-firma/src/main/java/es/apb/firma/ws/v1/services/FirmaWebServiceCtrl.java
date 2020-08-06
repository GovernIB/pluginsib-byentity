package es.apb.firma.ws.v1.services;

import java.io.File;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.springframework.stereotype.Component;

import es.apb.firma.ws.exception.WException;
import es.apb.firma.ws.interceptor.WebserviceExceptionInterceptor;
import es.apb.firma.ws.model.DatosCertificado;
import es.apb.firma.ws.model.ErrorFirmaWs;
import es.apb.firma.ws.model.RespuestaAFirma;
import es.apb.firma.ws.util.CertificadoUtils;
import es.apb.firma.ws.util.Configuracion;
import es.apb.firma.ws.util.IntegraUtils;
import es.apb.firma.ws.v1.model.FormatoFirma;
import es.apb.firma.ws.v1.model.PeticionFirmar;
import es.apb.firma.ws.v1.model.PeticionObtenerInfoCertificado;
import es.apb.firma.ws.v1.model.PeticionValidar;
import es.apb.firma.ws.v1.model.RespuestaFirmar;
import es.apb.firma.ws.v1.model.RespuestaObtenerInfoCertificado;
import es.apb.firma.ws.v1.model.RespuestaValidar;
//import es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerException;
//import es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerFacade;
import es.gob.afirma.signature.SigningException;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.utils.Base64CoderCommons;
import es.gob.afirma.utils.GeneralConstants;
import es.gob.afirma.utils.NativeTagsRequest;
import es.gob.afirma.wsServiceInvoker.Afirma5ServiceInvokerFacade;
import es.gob.afirma.wsServiceInvoker.WSServiceInvokerException;

/**
 *
 * Servicio web que permite realizar diversas acciones de firma. Entre las
 * opciones disponbiles:
 * <ul>
 * <li>Firmar un documento.</li>
 * <li>Validar una firma.</li>
 * </ul>
 *
 * @author Indra
 *
 */
@Component("firmaWebServiceCtrl")
public final class FirmaWebServiceCtrl implements FirmaWebService {

	/** Logger. **/
	static final Logger logger = Logger.getLogger(FirmaWebService.class);

	@Override
	@WebserviceExceptionInterceptor
	public RespuestaFirmar firmar(final PeticionFirmar peticion) throws WException {

		// Obtiene datos a firmar y certificado/formato a usar
		final byte[] dataToSign = peticion.getDocumento();
		String aliasCertificado = peticion.getAliasCertificado();
		if (aliasCertificado == null) {
			aliasCertificado = Configuracion.getInstance().getDefaultCertificate();
		}
		final FormatoFirma formato;
		if (peticion.getFormato() == null) {
			formato = FormatoFirma.valueOf(Configuracion.getInstance().getDefaultFormat());
		} else {
			formato = peticion.getFormato();
		}

		// Realiza la firma
		final byte[] signature = firmarImpl(aliasCertificado, dataToSign, formato);

		// Obtenemos info del certificado
		final String certificadoB64 = IntegraUtils.getCertificateFromSignature(signature, formato);
		final RespuestaAFirma respValidarCertInfo = obtenerInfoCertificadoImpl(certificadoB64);

		// Interpretamos respuesta afirma
		final DatosCertificado dc = CertificadoUtils.getDatosCertificado(respValidarCertInfo);

		// Devuelve respuesta
		final RespuestaFirmar respuesta = new RespuestaFirmar();
		respuesta.setFormato(formato);
		respuesta.setFirma(signature);
		respuesta.setNif(dc.getNif());
		respuesta.setNombreApellidos(dc.getNombreApellidos());
		respuesta.setCertificadoB64(certificadoB64);

		if (dc.getNifRepresentante() != null) {
			respuesta.setNifRepresentante(dc.getNifRepresentante());
			respuesta.setNombreApellidosRepresentante(dc.getNombreApellidosRepresentante());
		}

		return respuesta;
	}

	/**
	 * @param aliasCertificado
	 * @param dataToSign
	 * @param formato
	 * @return
	 */
	private byte[] firmarImpl(final String aliasCertificado, final byte[] dataToSign, final FormatoFirma formato) {
		final byte[] signature;
		try {
			switch (formato) {
			case CADES_DETACHED:
				signature = IntegraUtils.firmaCades(dataToSign, aliasCertificado);
				break;
			case XADES_DETACHED:
				signature = IntegraUtils.firmaXades(dataToSign, aliasCertificado);
				break;
			case PADES:
				signature = IntegraUtils.firmaPades(dataToSign, aliasCertificado);
				break;
			default:
				throw new WException(ErrorFirmaWs.ERROR_FORMATO_FIRMA_NO_SOPORTADO, "Formato de firma no soportado",
						formato.name(), null, null);
			}
		} catch (final SigningException e) {
			throw new WException(ErrorFirmaWs.ERROR_FIRMA, "Error al firmar " + formato.name(), e.getMessage(), null,
					e);
		}
		return signature;
	}

	@Override
	@WebserviceExceptionInterceptor
	public RespuestaValidar validar(final PeticionValidar peticion) throws WException {

		logger.debug("Peticion validar firma...");

		// Obtenemos de la peticion: firma, formato y documento firmado
		final byte[] signature = peticion.getFirma();
		final byte[] dataToSign = peticion.getDocumento();
		final FormatoFirma formato = peticion.getFormato();

		// Realizamos invocaciones a AFirma para firmar y obtener info del
		// certificado
		final RespuestaValidar respuesta = new RespuestaValidar();

		// Invoca a AFirma para validar firma
		logger.debug("Invocacion a AFirma para validar firma...");
		final RespuestaAFirma respValidarFirmaInfo = validarFirmaImpl(signature, formato, dataToSign);

		if (respValidarFirmaInfo.isResultado()) {
			// Firma correcta, obtenemos info certificado
			logger.debug("Firma correcta, invocacion a AFirma para obtener info certificado...");
			final String certificateB64 = respValidarFirmaInfo.getCertificateB64();
			final RespuestaAFirma respValidarCertInfo = obtenerInfoCertificadoImpl(certificateB64);

			final DatosCertificado dc = CertificadoUtils.getDatosCertificado(respValidarCertInfo);

			respuesta.setResultado(true);
			respuesta.setCertificadoB64(certificateB64);
			respuesta.setNif(dc.getNif());
			respuesta.setNombreApellidos(dc.getNombreApellidos());
			respuesta.setNifRepresentante(dc.getNifRepresentante());

			if (dc.getNifRepresentante() != null) {
				respuesta.setNifRepresentante(dc.getNifRepresentante());
				respuesta.setNombreApellidosRepresentante(dc.getNombreApellidosRepresentante());
			}

		} else {
			// Firma incorrecta
			respuesta.setResultado(false);
			respuesta.setDescripcionError(respValidarFirmaInfo.getDescripcionError());
		}

		return respuesta;

	}

	@Override
	@WebserviceExceptionInterceptor
	public RespuestaObtenerInfoCertificado obtenerInfoCertificado(final PeticionObtenerInfoCertificado peticion)
			throws WException {
		logger.debug("Invocacion a AFirma para obtener info certificado...");

		// Verificamos si se pasa una firma o el certificado
		if (peticion.getCertificadoB64() == null && peticion.getContenidoFirma() == null
				&& peticion.getFormatoFirma() == null) {
			throw new WException(ErrorFirmaWs.ERROR_FIRMA, "No se ha indicado certificado ni firma",
					"No se ha indicado certificado ni firma", null, null);
		}

		String certificadoB64 = null;

		if (peticion.getCertificadoB64() != null) {
			logger.debug("Se ha pasado como parametro el certificado...");
			certificadoB64 = peticion.getCertificadoB64();
		} else if (peticion.getContenidoFirma() != null && peticion.getFormatoFirma() != null) {
			logger.debug("Se ha pasado como parametro la firma y formato...");
			certificadoB64 = IntegraUtils.getCertificateFromSignature(peticion.getContenidoFirma(),
					peticion.getFormatoFirma());
		} else {
			logger.debug("Falta la firma o el formato");
			throw new WException(ErrorFirmaWs.ERROR_FIRMA, "Debe establecerse la firma y el formato de firma",
					"Debe establecerse la firma y el formato de firma", null, null);
		}

		// Obtenemos info del certificado
		final RespuestaObtenerInfoCertificado respuesta = new RespuestaObtenerInfoCertificado();
		final RespuestaAFirma respValidarCertInfo = obtenerInfoCertificadoImpl(certificadoB64);

		final DatosCertificado dc = CertificadoUtils.getDatosCertificado(respValidarCertInfo);

		respuesta.setNif(dc.getNif());
		respuesta.setNombreApellidos(dc.getNombreApellidos());
		respuesta.setCertificadoB64(certificadoB64);
		if (dc.getNifRepresentante() != null) {
			respuesta.setNifRepresentante(dc.getNifRepresentante());
			respuesta.setNombreApellidosRepresentante(dc.getNombreApellidosRepresentante());
		}
		return respuesta;
	}

	// -- Funciones auxiliares

	/**
	 * Valida certificado contra AFirma.
	 *
	 * @param certificateB64
	 * @return info certificado
	 */
	private RespuestaAFirma obtenerInfoCertificadoImpl(final String certificateB64) {
		try {
			final RespuestaAFirma respValidarCertInfo = new RespuestaAFirma();

			logger.debug("Prepara peticion para AFirma...");
			final String applicationName = Configuracion.getInstance().getApplicationName();
			Map<String, Object> inParams = new HashMap<String, Object>();
			inParams = new HashMap<String, Object>();
			inParams.put(NativeTagsRequest.ID_APLICACION, applicationName);
			inParams.put(NativeTagsRequest.CERTIFICADO, certificateB64);
			final String xmlInput = TransformersFacade.getInstance().generateXml(inParams,
					GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO,
					TransformersConstants.VERSION_10);

			logger.debug("Realiza invocacion a AFirma...");
			// logger.debug("XML Peticion @firma " +
			// GeneralConstants.OBTENER_INFO_CERTIFICADO + " :" + xmlInput);
			final String xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput,
					GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO,
					applicationName);

			logger.debug("Interpreta respuesta AFirma...");
			// logger.debug("XML Respuesta @firma " +
			// GeneralConstants.OBTENER_INFO_CERTIFICADO + " :" + xmlOutput);
			final Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput,
					GeneralConstants.OBTENER_INFO_CERTIFICADO, GeneralConstants.OBTENER_INFO_CERTIFICADO,
					TransformersConstants.VERSION_10);

			if (propertiesResult.get("InfoCertificado") != null) {
				logger.debug("Se ha encontrado info certificado");
				final Hashtable<String, Object> hashInfoCertificado = (Hashtable<String, Object>) propertiesResult
						.get("InfoCertificado");
				buscarValoresProperties(hashInfoCertificado, respValidarCertInfo);
			} else {
				logger.debug("No existe info certificado, generamos excepcion");
				throw new WException(ErrorFirmaWs.ERROR_TRANSFORMACION_XML,
						"No existe info certificado en la respuesta", null, null, null);
			}

			return respValidarCertInfo;
		} catch (final TransformersException e) {
			throw new WException(ErrorFirmaWs.ERROR_TRANSFORMACION_XML, "Error al transformar xml", e.getMessage(),
					null, e);
		} catch (final WSServiceInvokerException e) {
			throw new WException(ErrorFirmaWs.ERROR_CONEXION_AFIRMA, "Error al acceder a @firma", e.getMessage(), null,
					e);
		}

	}

	/**
	 * Invocacion a AFirma para validar firma
	 *
	 * @param signature  firma
	 * @param formato    formato
	 * @param dataToSign datos firmados
	 * @return
	 */
	private RespuestaAFirma validarFirmaImpl(final byte[] signature, final FormatoFirma formato,
			final byte[] dataToSign) {

		try {

			// Vemos si se hace debug de la validacion
			if (Configuracion.getInstance().isDebugValidacionFirmas()) {
				try {
					final String dir = Configuracion.getInstance().getDirectorioDebugValidacionFirmas();
					final File fileData = new File(dir + "dataToSign");
					final File fileSignature = new File(dir + "signature");
					FileUtils.deleteQuietly(fileData);
					FileUtils.deleteQuietly(fileSignature);
					if (dataToSign != null) {
						FileUtils.writeByteArrayToFile(fileData, dataToSign);
					}
					FileUtils.writeByteArrayToFile(fileSignature, signature);
				} catch (final Exception ex) {
					logger.error("No se ha podido debugear la validacion de firma", ex);
				}

			}

			final RespuestaAFirma respValidarFirmaInfo = new RespuestaAFirma();

			logger.debug("Prepara peticion para AFirma...");
			final String applicationName = Configuracion.getInstance().getApplicationName();
			final Map<String, Object> inParamsFirma = new HashMap<String, Object>();
			inParamsFirma.put(NativeTagsRequest.ID_APLICACION, applicationName);
			inParamsFirma.put(NativeTagsRequest.FIRMA_ELECTRONICA,
					new String(Base64CoderCommons.encodeBase64(signature)));
			if (dataToSign != null) {
				inParamsFirma.put("parametros/datos", new String(Base64CoderCommons.encodeBase64(dataToSign)));
			}
			inParamsFirma.put(NativeTagsRequest.FORMATO_FIRMA, IntegraUtils.getFormatoFirma(formato));
			final String xmlInput = TransformersFacade.getInstance().generateXml(inParamsFirma,
					GeneralConstants.VALIDAR_FIRMA_REQUEST, TransformersConstants.VERSION_10);

			logger.debug("Realiza invocacion a AFirma...");
			// logger.debug("XML Peticion @firma " + GeneralConstants.VALIDAR_FIRMA_REQUEST
			// + " :" + xmlInput);
			final Afirma5ServiceInvokerFacade afirmaInvoker = Afirma5ServiceInvokerFacade.getInstance();

			final String xmlOutputFirma = afirmaInvoker.invokeService(xmlInput, GeneralConstants.VALIDAR_FIRMA_REQUEST,
					GeneralConstants.VALIDAR_FIRMA_REQUEST, applicationName);

			logger.debug("Interpreta respuesta AFirma...");
			// logger.debug("XML Respuesta @firma " + GeneralConstants.VALIDAR_FIRMA_REQUEST
			// + " :" + xmlOutputFirma);
			final Map<String, Object> propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutputFirma,
					GeneralConstants.VALIDAR_FIRMA_REQUEST, GeneralConstants.VALIDAR_FIRMA_REQUEST,
					TransformersConstants.VERSION_10);

			if (propertiesResult.get("estado") == null || "false".equals(propertiesResult.get("estado").toString())) {
				// Firma incorrecta
				respValidarFirmaInfo.setResultado(false);
				respValidarFirmaInfo.setDescripcionError(propertiesResult.get("descripcion").toString());
				logger.debug("Firma incorrecta: " + respValidarFirmaInfo.getDescripcionError());
			} else {
				// Firma correcta, buscamos info de la firma
				logger.debug("Firma correcta");
				respValidarFirmaInfo.setResultado(true);
				buscarValoresProperties((Hashtable<String, Object>) propertiesResult, respValidarFirmaInfo);
				// En validar firma no se pasa por aquí.
				// respValidarFirmaInfo.prepararDatosObtenerInfoCertificado();
			}

			return respValidarFirmaInfo;

		} catch (final TransformersException e) {
			throw new WException(ErrorFirmaWs.ERROR_TRANSFORMACION_XML, "Error al transformar xml", e.getMessage(),
					null, e);
		} catch (final WSServiceInvokerException e) {
			throw new WException(ErrorFirmaWs.ERROR_CONEXION_AFIRMA, "Error al acceder a @firma", e.getMessage(), null,
					e);
		}

	}

	/**
	 * Método que recorre una hashtable y va mostrando los respectivos valores.
	 * Además, en caso de encontrar el valor 'Certificado' lo guarda en una variable
	 * para posteriormente validar el certificado.
	 *
	 * @param hashtable El hastable que se deben añadir delante.
	 * @param respInfo  Info a devolver
	 */
	private void buscarValoresProperties(final Hashtable<String, Object> hashtable, final RespuestaAFirma respInfo) {

		final Enumeration<String> e = hashtable.keys();
		while (e.hasMoreElements()) {
			final String key = e.nextElement();
			if (hashtable.get(key).getClass().equals(Hashtable.class)) {
				buscarValoresProperties((Hashtable<String, Object>) hashtable.get(key), respInfo);
			} else {
				logger.debug(key + "=" + (hashtable.get(key).toString()));
				if ("clasificacion".equals(key)) {
					respInfo.setClasificacion(hashtable.get(key).toString());
				}
				if ("certificado".equals(key)) {
					respInfo.setCertificateB64(hashtable.get(key).toString());
				}
				if ("NIFResponsable".equals(key)) {
					respInfo.setNifResponsable(hashtable.get(key).toString());
				}
				if ("NombreApellidosResponsable".equals(key)) {
					respInfo.setNombreApellidosResponsable(hashtable.get(key).toString());
				}
				if ("NIFEntidadSuscriptora".equals(key)) {
					respInfo.setNifEntidadSuscriptora(hashtable.get(key).toString());
				}
				if ("organizacion".equals(key)) {
					respInfo.setOrganizacion(hashtable.get(key).toString());
				}
				if ("razonSocial".equals(key)) {
					respInfo.setRazonSocial(hashtable.get(key).toString());
				}
				if ("NIF-CIF".equals(key)) {
					respInfo.setNifCif(hashtable.get(key).toString());
				}
			}
		}
	}

}
