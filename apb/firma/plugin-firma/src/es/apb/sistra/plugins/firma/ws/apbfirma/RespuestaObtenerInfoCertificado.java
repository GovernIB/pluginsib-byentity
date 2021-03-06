
package es.apb.sistra.plugins.firma.ws.apbfirma;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for respuestaObtenerInfoCertificado complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="respuestaObtenerInfoCertificado">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="nif" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="nombreApellidos" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="certificadoB64" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="nifRepresentante" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="nombreApellidosRepresentante" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "respuestaObtenerInfoCertificado", propOrder = {
    "nif",
    "nombreApellidos",
    "certificadoB64",
    "nifRepresentante",
    "nombreApellidosRepresentante"
})
public class RespuestaObtenerInfoCertificado {

    @XmlElement(required = true)
    protected String nif;
    @XmlElement(required = true)
    protected String nombreApellidos;
    @XmlElement(required = true)
    protected String certificadoB64;
    protected String nifRepresentante;
    protected String nombreApellidosRepresentante;

    /**
     * Gets the value of the nif property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNif() {
        return nif;
    }

    /**
     * Sets the value of the nif property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNif(String value) {
        this.nif = value;
    }

    /**
     * Gets the value of the nombreApellidos property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNombreApellidos() {
        return nombreApellidos;
    }

    /**
     * Sets the value of the nombreApellidos property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNombreApellidos(String value) {
        this.nombreApellidos = value;
    }

    /**
     * Gets the value of the certificadoB64 property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCertificadoB64() {
        return certificadoB64;
    }

    /**
     * Sets the value of the certificadoB64 property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCertificadoB64(String value) {
        this.certificadoB64 = value;
    }

    /**
     * Gets the value of the nifRepresentante property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNifRepresentante() {
        return nifRepresentante;
    }

    /**
     * Sets the value of the nifRepresentante property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNifRepresentante(String value) {
        this.nifRepresentante = value;
    }

    /**
     * Gets the value of the nombreApellidosRepresentante property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNombreApellidosRepresentante() {
        return nombreApellidosRepresentante;
    }

    /**
     * Sets the value of the nombreApellidosRepresentante property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNombreApellidosRepresentante(String value) {
        this.nombreApellidosRepresentante = value;
    }

}
