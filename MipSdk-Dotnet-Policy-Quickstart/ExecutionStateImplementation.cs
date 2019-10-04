using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.InformationProtection;
using Microsoft.InformationProtection.Policy;
using Microsoft.InformationProtection.Policy.Actions;

namespace MipSdk_Dotnet_Policy_Quickstart
{
    public struct ExecutionStateOptions
    {
        //public List<KeyValuePair<string, string>> metadata;
        public Dictionary<string, string> metadata;
        public Microsoft.InformationProtection.Label newLabel;
        public string contentIdentifier;
        public ActionSource actionSource;
        public DataState dataState;
        public AssignmentMethod assignmentMethod;
        public bool isDowngradeJustified;
        public string templateId;
        public ContentFormat contentFormat;
        public ActionType supportedActions;
        public bool generateAuditEvent;
        public string downgradeJustification;
    }

    public class ExecutionStateImplementation : ExecutionState
    {
        private ExecutionStateOptions _executionStateOptions;

        public ExecutionStateImplementation(ExecutionStateOptions executionStateOptions)
        {
            _executionStateOptions = executionStateOptions;
        }

        public override ContentFormat GetContentFormat()
        {
            return _executionStateOptions.contentFormat;
        }

        public override string GetContentIdentifier()
        {
            return _executionStateOptions.contentIdentifier;
        }

        public override List<KeyValuePair<string, string>> GetContentMetadata(List<string> names, List<string> namePrefixes)
        {
            Dictionary<string, string> filteredMetadata = new Dictionary<string, string>();

            foreach(var namePrefix in namePrefixes)
            {
                foreach (var prop in _executionStateOptions.metadata)
                {
                    if(prop.Key.StartsWith(namePrefix))
                    {
                        filteredMetadata.Add(prop.Key, prop.Value);
                    }
                }
            }

            foreach (var name in names)
            {
                string value = string.Empty;
                var itName = _executionStateOptions.metadata.TryGetValue(name, out value);
                filteredMetadata.Add(name, value);
            }

            List<KeyValuePair<string, string>> result = new List<KeyValuePair<string, string>>();

            foreach(var item in filteredMetadata)
            {
                result.Add(new KeyValuePair<string, string>(item.Key, item.Value));
            }

            return result;
        }

        public override Microsoft.InformationProtection.Label GetNewLabel()
        {
            return _executionStateOptions.newLabel;
        }

        public override AssignmentMethod GetNewLabelAssignmentMethod()
        {
            return _executionStateOptions.assignmentMethod;
        }

        public override ProtectionDescriptor GetProtectionDescriptor()
        {
            return new ProtectionDescriptor(_executionStateOptions.templateId);
        }

        /// <summary>
        ///  The UPE SDK will always notify client of 'JUSTIFY', 'METADATA', and 'REMOVE*' actions. However an application can
        ///  choose not to support specific actions that may appear in a policy. (For instance, A policy may define a label to
        ///  require both protection and a watermark, but the application could decide not to support watermarks by not
        ///  including ADD_WATERMARK here. If that were the case, 'mip::PolicyEngine::ComputeActions' would never return
        ///  AddWatermark actions.)
        /// </summary>
        /// <returns></returns>
        public override ActionType GetSupportedActions()
        {
            return ActionType.Metadata |
                ActionType.Custom |
                ActionType.ProtectAdhoc |
                ActionType.ProtectByTemplate |
                ActionType.ProtectDoNotForward |
                ActionType.RemoveProtection |
                ActionType.Justify;
        }

        public override bool IsDowngradeJustified(out string justificationMessage)
        {
            justificationMessage = _executionStateOptions.downgradeJustification;
            return _executionStateOptions.isDowngradeJustified;
        }        
    }
}
