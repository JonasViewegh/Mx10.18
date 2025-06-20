// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package saml20.actions;

import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import com.mendix.webui.CustomJavaAction;
import saml20.implementation.common.MendixUtils;
import saml20.implementation.security.CertificateHandler;
import saml20.proxies.*;
import java.util.HashMap;
import java.util.List;

public class ReEvaluateImportedData extends CustomJavaAction<java.lang.Boolean>
{
	/** @deprecated use IdPFile.getMendixObject() instead. */
	@java.lang.Deprecated(forRemoval = true)
	private final IMendixObject __IdPFile;
	private final saml20.proxies.IdPMetadata IdPFile;

	public ReEvaluateImportedData(
		IContext context,
		IMendixObject _idPFile
	)
	{
		super(context);
		this.__IdPFile = _idPFile;
		this.IdPFile = _idPFile == null ? null : saml20.proxies.IdPMetadata.initialize(getContext(), _idPFile);
	}

	@java.lang.Override
	public java.lang.Boolean executeAction() throws Exception
	{
		// BEGIN USER CODE

        @SuppressWarnings("serial")
        List<IMendixObject> result = MendixUtils.retrieveFromDatabase(getContext(), "//%s[%s/%s [%s/%s/%s/%s/%s = $idpFileId or %s/%s/%s/%s/%s/%s/%s/%s/%s = $idpFileId or %s/%s/%s = $idpFileId]]",
                new HashMap<String, Object>() {{
                    put("idpFileId", IdPFile.getMendixObject().getId());
                }},
                X509Certificate.entityName,
                KeyInfo.MemberNames.KeyInfo_X509Certificate.toString(),
                KeyInfo.entityName,

                KeyInfo.MemberNames.KeyInfo_EntityDescriptor.toString(),
                EntityDescriptor.entityName,
                EntityDescriptor.MemberNames.EntityDescriptor_EntitiesDescriptor.toString(),
                EntitiesDescriptor.entityName,
                EntitiesDescriptor.MemberNames.EntitiesDescriptor_IdPMetadata.toString(),

                KeyDescriptor.MemberNames.KeyDescriptor_KeyInfo.toString(),
                KeyDescriptor.entityName,
                KeyDescriptor.MemberNames.KeyDescriptor_RoleDescriptor.toString(),
                RoleDescriptor.entityName,
                RoleDescriptor.MemberNames.RoleDescriptor_EntityDescriptor.toString(),
                EntityDescriptor.entityName,
                EntityDescriptor.MemberNames.EntityDescriptor_EntitiesDescriptor.toString(),
                EntitiesDescriptor.entityName,
                EntitiesDescriptor.MemberNames.EntitiesDescriptor_IdPMetadata.toString(),

                EntitiesDescriptor.MemberNames.EntitiesDescriptor_KeyInfo.toString(),
                EntitiesDescriptor.entityName,
                EntitiesDescriptor.MemberNames.EntitiesDescriptor_IdPMetadata.toString()
        );

        for (IMendixObject certObj : result) {
            CertificateHandler.extractCertificateMetaData(this.getContext(), certObj);
        }
        Core.commit(getContext(), result);

        return true;
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 * @return a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "ReEvaluateImportedData";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
