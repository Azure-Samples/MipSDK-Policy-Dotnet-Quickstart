using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.InformationProtection;
using Microsoft.InformationProtection.Policy.Actions;
using Label = Microsoft.InformationProtection.Label;

namespace MipSdk_Dotnet_Policy_Quickstart
{
    class Program
    {
        private static readonly string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static readonly string appName = ConfigurationManager.AppSettings["app:Name"];
        private static readonly string appVersion = ConfigurationManager.AppSettings["app:Version"];

        static void Main(string[] args)
        {
            // Create ApplicationInfo, setting the clientID from Azure AD App Registration as the ApplicationId
            // If any of these values are not set API throws BadInputException.
            ApplicationInfo appInfo = new ApplicationInfo()
            {
                // ApplicationId should ideally be set to the same ClientId found in the Azure AD App Registration.
                // This ensures that the clientID in AAD matches the AppId reported in AIP Analytics.
                ApplicationId = clientId,
                ApplicationName = appName,
                ApplicationVersion = appVersion
            };

            string newLabelId = string.Empty;
            string currentLabelId = string.Empty;

            // Initialize Action class, passing in AppInfo.
            Action action = new Action(appInfo);

            // List all labels available to the engine created in Action
            IEnumerable<Label> labels = action.ListLabels();


            // Enumerate parent and child labels and print name/ID. 
            foreach (var label in labels)
            {
                Console.WriteLine(string.Format("{0} - {1}", label.Name, label.Id));

                if (label.Children.Count > 0)
                {
                    foreach (Label child in label.Children)
                    {
                        Console.WriteLine(string.Format("\t{0} - {1}", child.Name, child.Id));
                    }
                }
            }

            Console.Write("Enter a label ID: ");
            currentLabelId =  Console.ReadLine();

            Console.Write("Enter a new label ID: ");
            newLabelId = Console.ReadLine();

            ExecutionStateOptions options = new ExecutionStateOptions();

            options.newLabel = action.GetLabelById(currentLabelId);
            options.actionSource = ActionSource.Manual;
            options.assignmentMethod = AssignmentMethod.Standard;
            options.contentFormat = Microsoft.InformationProtection.Policy.ContentFormat.Default;
            options.contentIdentifier = "MyTestFile.pptx";
            options.dataState = DataState.Use;
            options.isDowngradeJustified = false;
            options.generateAuditEvent = true;
            options.metadata = new Dictionary<string, string>();

            var initialActions = action.ComputeActions(options);

            // If you need addition actions, modify GetSupportedActions in ExecutionStateImplementation.cs
            // Then, iterate through teh actions for the one you care about, say, apply header, footer, or watermark. 
            // From those derived actions, you'll be able to get the content marking information.
            foreach(var item in initialActions)
            {
                switch(item.ActionType)
                {
                    case ActionType.Metadata:

                        options.metadata.Clear();
                        
                        foreach (var data in ((MetadataAction)item).MetadataToAdd)
                        {
                            options.metadata.Add(data.Key, data.Value);
                        }
                        break;

                    case ActionType.ProtectByTemplate:

                        options.templateId = ((ProtectByTemplateAction)item).TemplateId;

                        break;
                    default:
                        break;
                }
            }

            options.newLabel = action.GetLabelById(newLabelId);

            var result = action.ComputeActionLoop(options);

            Console.WriteLine("Press a key to quit.");
            Console.ReadKey();
        }
    }
}
