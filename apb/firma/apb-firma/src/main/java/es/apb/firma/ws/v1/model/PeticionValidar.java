package es.apb.firma.ws.v1.model;
 
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import es.apb.firma.ws.v1.model.FormatoFirma;

/**
 * Peticion de validar un documento y su firma.
 * 
 * @author indra
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
public final class PeticionValidar {

    /**
     * Documento para firmar en texto.
     */
    @XmlElement(required = true)
    private byte[] documento;

    /**
     * Documento para firmar en texto.
     */
    @XmlElement(required = true)
    private byte[] firma;
    
    /**
     * Formato: CADES, XADES.
     */
    @XmlElement(required = true)
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
     * @return the firma
     */
    public byte[] getFirma() {
        return firma;
    }

    /**
     * @param iFirma the firma to set
     */
    public void setFirma(final byte[] iFirma) {
        this.firma = iFirma;
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

}
