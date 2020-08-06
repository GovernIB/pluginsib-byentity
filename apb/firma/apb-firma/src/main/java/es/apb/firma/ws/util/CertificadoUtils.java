package es.apb.firma.ws.util;

import org.apache.cxf.common.util.StringUtils;

import es.apb.firma.ws.exception.WException;
import es.apb.firma.ws.model.DatosCertificado;
import es.apb.firma.ws.model.ErrorFirmaWs;
import es.apb.firma.ws.model.RespuestaAFirma;

/**
 * Obtiene info a partir del resultado del certifcado.
 * 
 * @author Indra
 * 
 */
public class CertificadoUtils {

    /**
     * Obtiene DatosCertificado.
     * 
     * @param ri
     *            Respuesta Cl@veFirma
     * @return DatosCertificado
     */
    public static DatosCertificado getDatosCertificado(final RespuestaAFirma ri) {
        final DatosCertificado res = new DatosCertificado();

        final String clasificacion = ri.getClasificacion();

        if ("4".equals(clasificacion) || "8".equals(clasificacion)) {
            // Sello de organo
            res.setNif(ri.getNifEntidadSuscriptora());
            res.setNombreApellidos(ri.getOrganizacion());
        } else if ("0".equals(clasificacion) || "5".equals(clasificacion)) {
            // - Persona fisica (0) / Empleado publico (5)
            res.setNif(ri.getNifResponsable());
            res.setNombreApellidos(ri.getNombreApellidosResponsable());
        } else if ("1".equals(clasificacion)) {
            // Persona juridica (1)
            res.setNif(ri.getNifCif());
            res.setNombreApellidos(ri.getRazonSocial());
        } else if ("11".equals(clasificacion) || "12".equals(clasificacion)) {
            // - Representante Entidad (11) / Representante Entidad sin
            // personalidad juridica (12)
            res.setNif(ri.getNifCif());
            res.setNombreApellidos(ri.getRazonSocial());
            res.setNifRepresentante(ri.getNifResponsable());
            res.setNombreApellidosRepresentante(ri
                    .getNombreApellidosResponsable());
        } else {
            // Resto no soportados
            throw new WException(ErrorFirmaWs.ERROR_CERTIFICADO_NO_SOPORTADO,
                    "Certificado tipo " + clasificacion + " no soportado.", null, null, null);
        }

        // Si no están rellanos, lanzar error!
        if (StringUtils.isEmpty(res.getNif())) {
            throw new WException(
                    ErrorFirmaWs.ERROR_CERTIFICADO_DATOS_INCOMPLETOS,
                    "Los datos del certificado están incompletos.", null, null,
                    null);
        }

        return res;
    }
}
