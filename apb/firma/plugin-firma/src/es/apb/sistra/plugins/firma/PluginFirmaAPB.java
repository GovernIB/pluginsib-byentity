package es.apb.sistra.plugins.firma;

import java.io.InputStream;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.apb.sistra.plugins.firma.ws.apbfirma.FirmaWebService;
import es.apb.sistra.plugins.firma.ws.apbfirma.FirmarRequest;
import es.apb.sistra.plugins.firma.ws.apbfirma.FirmarResponse;
import es.apb.sistra.plugins.firma.ws.apbfirma.FormatoFirma;
import es.apb.sistra.plugins.firma.ws.apbfirma.ObtenerInfoCertificadoRequest;
import es.apb.sistra.plugins.firma.ws.apbfirma.ObtenerInfoCertificadoResponse;
import es.apb.sistra.plugins.firma.ws.apbfirma.PeticionFirmar;
import es.apb.sistra.plugins.firma.ws.apbfirma.PeticionObtenerInfoCertificado;
import es.apb.sistra.plugins.firma.ws.apbfirma.PeticionValidar;
import es.apb.sistra.plugins.firma.ws.apbfirma.ValidarRequest;
import es.apb.sistra.plugins.firma.ws.apbfirma.ValidarResponse;
import es.caib.sistra.plugins.firma.FicheroFirma;
import es.caib.sistra.plugins.firma.FirmaIntf;
import es.caib.sistra.plugins.firma.PluginFirmaIntf;

public class PluginFirmaAPB implements PluginFirmaIntf {

    /** Log. */
    private static Log log = LogFactory.getLog(PluginFirmaAPB.class);

    /** Formato firma defecto. */
    private String formatoFirmaDefecto = null;

    /** Constructor. */
    public PluginFirmaAPB() {
        super();
        try {
            formatoFirmaDefecto = ConfigurationUtil.getInstance()
                    .obtenerPropiedades().getProperty("apb-firma.formato");
            if (StringUtils.isBlank(formatoFirmaDefecto)) {
                throw new Exception(
                        "No se ha indicado formato de firma a usar en el plugin");
            }
        } catch (final Exception ex) {
            throw new RuntimeException("Error obteniendo propiedades plugin",
                    ex);
        }
    }

    /**
     * Obtiene proveedor
     */
    @Override
    public String getProveedor() {
        return PluginFirmaIntf.PROVEEDOR_FIRMAWEB;
    }

    /**
     * Realiza firma
     */
    @Override
    public FirmaIntf firmar(final InputStream datos,
            final String nombreCertificado, final Map parametros)
            throws Exception {
        log.debug("Invocamos a apb-firma...");

        final PeticionFirmar peticionFirma = new PeticionFirmar();
        peticionFirma.setDocumento(IOUtils.toByteArray(datos));
        peticionFirma.setFormato(UtilFirmaAPB
                .traducirFormatoPlgFirmaToApb(formatoFirmaDefecto));
        peticionFirma.setAliasCertificado(nombreCertificado);

        final FirmarRequest requestFirma = new FirmarRequest();
        requestFirma.setPeticion(peticionFirma);

        final FirmaWebService clienteWs = UtilFirmaAPB.generarClienteApbFirma();
        final FirmarResponse responseFirma = clienteWs.firmar(requestFirma);
        log.debug("Obtenemos respuesta apb-firma...");

        final byte[] sign = responseFirma.getRespuesta().getFirma();
        final String formato = UtilFirmaAPB
                .traducirFormatoApbFirmaToPlgFirma(responseFirma.getRespuesta()
                        .getFormato());
        final String nif = responseFirma.getRespuesta().getNif();
        final String nomApe = responseFirma.getRespuesta().getNombreApellidos();
        final String certB64 = responseFirma.getRespuesta().getCertificadoB64();
        final String nifRpte = responseFirma.getRespuesta()
                .getNifRepresentante();
        final String nomApeRpte = responseFirma.getRespuesta()
                .getNombreApellidosRepresentante();

        final FirmaAPB f = new FirmaAPB(sign, formato, nif, nomApe, certB64,
                nifRpte, nomApeRpte);
        return f;
    }

    /**
     * Verifica firma
     */
    @Override
    public boolean verificarFirma(final InputStream datos, final FirmaIntf firma)
            throws Exception {
        log.debug("Invocamos a apb-firma...");
        final PeticionValidar peticionValidar = new PeticionValidar();
        FormatoFirma formatoFirmaAPB = UtilFirmaAPB
                .traducirFormatoPlgFirmaToApb(firma.getFormatoFirma());
        if (formatoFirmaAPB != FormatoFirma.PADES) {
        	peticionValidar.setDocumento(IOUtils.toByteArray(datos));
        }
        peticionValidar.setFirma(firma.getContenidoFirma());
		peticionValidar.setFormato(formatoFirmaAPB);
        final ValidarRequest validarRequest = new ValidarRequest();
        validarRequest.setPeticion(peticionValidar);

        final FirmaWebService clienteWs = UtilFirmaAPB.generarClienteApbFirma();
        final ValidarResponse responseValidar = clienteWs
                .validar(validarRequest);

        boolean res = false;
        try {
            res = (responseValidar.getRespuesta().isResultado());
        } catch (final Exception ex) {
            log.error("Error validando firma: " + ex.getMessage());
        }

        return res;
    }

    /**
     * Parsea la firma proveniente del html
     */
    @Override
    public FirmaIntf parseFirmaFromHtmlForm(final String signatureHtml)
            throws Exception {

        // Verificamos si la firma es PADES
        String formatoFirma = formatoFirmaDefecto;
        String signatureHtmlForm = signatureHtml;
        if (signatureHtml.startsWith("[FORMATO:PADES]")) {
            formatoFirma = FORMATO_FIRMA_PADES;
            signatureHtmlForm = signatureHtml.substring("[FORMATO:PADES]"
                    .length());
        }

        log.debug("Parse firma html: " + formatoFirma);

        final String signatureDataStr = UtilFirmaAPB
                .unescapeChars64UrlSafe(signatureHtmlForm);
        final byte[] signatureData = Base64.decodeBase64(signatureDataStr
                .getBytes());

        final FormatoFirma signatureFormat = UtilFirmaAPB
                .traducirFormatoPlgFirmaToApb(formatoFirma);

        final PeticionObtenerInfoCertificado peticionCert = new PeticionObtenerInfoCertificado();
        peticionCert.setContenidoFirma(signatureData);
        peticionCert.setFormatoFirma(signatureFormat);
        final ObtenerInfoCertificadoRequest requestCert = new ObtenerInfoCertificadoRequest();
        requestCert.setPeticion(peticionCert);

        final FirmaWebService clienteWs = UtilFirmaAPB.generarClienteApbFirma();
        final ObtenerInfoCertificadoResponse respCert = clienteWs
                .obtenerInfoCertificado(requestCert);

        final String nifRpte = respCert.getRespuesta().getNifRepresentante();
        final String nomApeRpte = respCert.getRespuesta()
                .getNombreApellidosRepresentante();

        final FirmaAPB f = new FirmaAPB(signatureData, formatoFirma, respCert
                .getRespuesta().getNif(), respCert.getRespuesta()
                .getNombreApellidos(), respCert.getRespuesta()
                .getCertificadoB64(), nifRpte, nomApeRpte);

        return f;
    }

    /**
     * Deserializa firma y la convierte en un objeto de firma
     */
    @Override
    public FirmaIntf parseFirmaFromBytes(final byte[] firmaBytes,
            final String formatoFirma) throws Exception {
        return UtilFirmaAPB.deserializaFirmaFromBytes(firmaBytes);
    }

    /**
     * Serializa firma para ser almacenada como un conjunto de bytes
     */
    @Override
    public byte[] parseFirmaToBytes(final FirmaIntf firma) throws Exception {
        return UtilFirmaAPB.serializaFirmaToBytes((FirmaAPB) firma);
    }

    /**
     * Genera fichero con la firma (SMIME)
     */
    @Override
    public FicheroFirma parseFirmaToFile(final InputStream datosFirmados,
            final FirmaIntf firma) throws Exception {
        final FicheroFirma ff = new FicheroFirma();
        ff.setContenido(firma.getContenidoFirma());
        if (PluginFirmaIntf.FORMATO_FIRMA_XADES_DETACHED.equals(firma
                .getFormatoFirma())) {
            ff.setNombreFichero("firma.xml");
        } else if (PluginFirmaIntf.FORMATO_FIRMA_CADES_DETACHED.equals(firma
                .getFormatoFirma())) {
            ff.setNombreFichero("firma.cades");
        } else if (PluginFirmaIntf.FORMATO_FIRMA_PADES.equals(firma
                .getFormatoFirma())) {
            ff.setNombreFichero("firma.pdf");
        } else {
            throw new Exception("Formato no soportado");
        }
        return ff;
    }

    /**
     * Parseo firma de los webservices de sistra.
     */
    @Override
    public FirmaIntf parseFirmaFromWS(final byte[] firmaBytes,
            final String formatoFirma) throws Exception {
        return parseFirmaFromBytes(firmaBytes, formatoFirma);
    }

    /**
     * Parseo firma de los webservices de sistra.
     */
    @Override
    public byte[] parseFirmaToWS(final FirmaIntf firma) throws Exception {
        return parseFirmaToBytes(firma);
    }

}
