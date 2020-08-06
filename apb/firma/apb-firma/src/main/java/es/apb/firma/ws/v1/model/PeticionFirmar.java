package es.apb.firma.ws.v1.model;
 
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import es.apb.firma.ws.v1.model.FormatoFirma;

/**
 * Peticion de firmar un documento.
 * 
 * @author indra
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
public final class PeticionFirmar {

    
    /**
     * Documento para firmar en texto.
     */
    @XmlElement(required = true)
    private byte[] documento;

   /**
     * Alias para el certificado.
     */
    @XmlElement(required = false)
    private String aliasCertificado;

    
    /**
    * Formato: CADES, XADES.
    */
    @XmlElement(required = false)
    private FormatoFirma formato;
    
    /**
    * @return the documento
    */
    public byte[] getDocumento() {
        return documento;
    }

    /**
     * @param iDocumento the documento to set
     */
    public void setDocumento(final byte[] iDocumento) {
        this.documento = iDocumento;
    }

    

    /**
     * @return the formato
     */
    public FormatoFirma getFormato() {
        return formato;
    }

    /**
     * @param iFormato the formato to set
     */
    public void setFormato(final FormatoFirma iFormato) {
        this.formato = iFormato;
    }
    
    
    /**
     * @return the aliasCertificado
     */
    public String getAliasCertificado() {
        return aliasCertificado;
    }

    /**
     * @param iAliasCertificado the aliasCertificado to set
     */
    public void setAliasCertificado(final String iAliasCertificado) {
        this.aliasCertificado = iAliasCertificado;
    }


}
