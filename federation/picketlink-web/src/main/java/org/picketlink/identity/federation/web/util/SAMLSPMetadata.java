package org.picketlink.identity.federation.web.util;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.util.SAMLMetadataUtil;
import org.picketlink.identity.federation.saml.v2.metadata.AttributeConsumingServiceType;
import org.picketlink.identity.federation.saml.v2.metadata.EndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.EntitiesDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType.EDTChoiceType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType.EDTDescriptorChoiceType;
import org.picketlink.identity.federation.saml.v2.metadata.IndexedEndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.KeyDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.KeyTypes;
import org.picketlink.identity.federation.saml.v2.metadata.RequestedAttributeType;
import org.picketlink.identity.federation.saml.v2.metadata.SPSSODescriptorType;

/**
 * @author Charles Zhao
 *
 */
public class SAMLSPMetadata {
    private static Logger log = Logger.getLogger(SAMLSPMetadata.class);

	private static Map<String, SPSSODescriptorType> spDescriptors = new HashMap<String, SPSSODescriptorType>();
	
	public static void init(InputStream is) throws ParsingException {
		log.info("Initialzing Service Providers Metadata, input stream: " + is);
		
		if (is == null) {
			return;
		}

		SAMLParser samlParser = new SAMLParser();
		EntitiesDescriptorType entitiesDescriptor = (EntitiesDescriptorType) samlParser
				.parse(is);

		spDescriptors.clear();
		
		for (Object object : entitiesDescriptor.getEntityDescriptor()) {
			if (object instanceof EntityDescriptorType) {
				EntityDescriptorType entityDescriptor = (EntityDescriptorType) object;
				String entityId = entityDescriptor.getEntityID();

				for (EDTChoiceType edt : entityDescriptor.getChoiceType()) {
					List<EDTDescriptorChoiceType> descriptors = edt
							.getDescriptors();
					for (EDTDescriptorChoiceType edtDesc : descriptors) {
						SPSSODescriptorType spSSODescriptorType = edtDesc
								.getSpDescriptor();
						if (spSSODescriptorType != null) {
							log.info("Adding SPSSODescriptorType for SP Entity ID: " + entityId);
							spDescriptors.put(entityId, spSSODescriptorType);
						}
					}
				}

			}
		}
	}
	
	public static String getAssertionConsumerServiceEndpoint(String spEntityId) {
		SPSSODescriptorType spssoDescriptorType = getSSODescriptorType(spEntityId);
		
		List<IndexedEndpointType> assertionConsumerServices = spssoDescriptorType.getAssertionConsumerService();
		
		if ( assertionConsumerServices != null && assertionConsumerServices.size() > 0 ) {
			return assertionConsumerServices.get(0).getLocation().toString();
		}
		
		return null;
	}
	
	public static String getSingleLogoutServiceEndpoint(String spEntityId) {
		SPSSODescriptorType spssoDescriptorType = getSSODescriptorType(spEntityId);
		
		if ( spssoDescriptorType == null ) {
			return null;
		}
		
		List<EndpointType> singleLogoutServices = spssoDescriptorType.getSingleLogoutService();
		
		if ( singleLogoutServices != null && singleLogoutServices.size() > 0 ) {
			return singleLogoutServices.get(0).getResponseLocation().toString();
		}
		
		return null;
	}
	
	public static X509Certificate getEncryptionCert(String spEntityId) {
		return getCert(spEntityId, KeyTypes.ENCRYPTION);
	}
	
	public static X509Certificate getSigningCert(String spEntityId) {
		return getCert(spEntityId, KeyTypes.SIGNING);
	}
	
	public static X509Certificate getCert(String spEntityId, KeyTypes keytype) {
		SPSSODescriptorType spssoDescriptorType = getSSODescriptorType(spEntityId);
		
        if ( spssoDescriptorType != null ) {
      	  for ( KeyDescriptorType keyDescriptor : spssoDescriptorType.getKeyDescriptor() ) {
      		  try {
      			  if ( keyDescriptor.getUse().equals(keytype) ) {
      			  	return SAMLMetadataUtil.getCertificate(keyDescriptor);
      			  }
      		  } catch (Exception e) {
      			  log.error("Unable to get X509 certificate from KeyDescriptorType.", e);
      		  }
      	  }
        }
        
        return null;		
	}
	
	public static List<String> getRequestedAttributes(String spEntityId, Integer attributeConsumerServiceIndex) {
		SPSSODescriptorType spssoDescriptorType = spDescriptors.get(spEntityId);
		
		if ( spssoDescriptorType != null ) {
			for ( AttributeConsumingServiceType attributeConsumingServiceType : spssoDescriptorType.getAttributeConsumingService() ) {
				if ( attributeConsumerServiceIndex != null ) {
					if ( attributeConsumerServiceIndex == attributeConsumingServiceType.getIndex() ) {
						return getRequestedAttributes(attributeConsumingServiceType);
					}
				} else if ( attributeConsumingServiceType.isIsDefault() != null && attributeConsumingServiceType.isIsDefault() ) {
					return getRequestedAttributes(attributeConsumingServiceType);
				}
			}
		}
			
		return new ArrayList<String>();
	}

	private static List<String> getRequestedAttributes(AttributeConsumingServiceType attributeConsumingServiceType) {
		List<RequestedAttributeType> requestedAttributes = attributeConsumingServiceType.getRequestedAttribute();
		
		List<String> result = new ArrayList<String>();
		
		for (RequestedAttributeType requestedAttributeType : requestedAttributes) {
			result.add(requestedAttributeType.getName());
		}
		
		return result;
	}

	private static SPSSODescriptorType getSSODescriptorType(String spEntityId) {
		SPSSODescriptorType spssoDescriptorType = spDescriptors.get(spEntityId);
		
		if ( spssoDescriptorType == null ) {
			if ( log.isDebugEnabled() ) {
				log.debug("Unable to find SPSSOEntityDescriptor for entity id: " + spEntityId);
			}
			return null;
		}
		return spssoDescriptorType;
	}
}
