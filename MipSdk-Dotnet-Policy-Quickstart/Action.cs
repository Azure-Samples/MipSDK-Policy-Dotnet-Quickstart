/*
*
* Copyright (c) Microsoft Corporation.
* All rights reserved.
*
* This code is licensed under the MIT License.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files(the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions :
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*
*/

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Markup;
using Microsoft.InformationProtection;
using Microsoft.InformationProtection.Exceptions;
using Microsoft.InformationProtection.Policy;
using Microsoft.InformationProtection.Policy.Actions;

namespace MipSdk_Dotnet_Policy_Quickstart
{
    /// <summary>
    /// Action class implements the various MIP functionality.
    /// For this sample, only profile, engine, and handler creation are defined. 
    /// The IFileHandler may be used to label a file and read a labeled file.
    /// </summary>
    public class Action
    {
        private AuthDelegateImplementation authDelegate;
        private ApplicationInfo appInfo;
        private IPolicyProfile profile;
        private IPolicyEngine engine;
        private MipContext mipContext;

        // Use Execution State to compute policy actions                

        /// <summary>
        /// Constructor for Action class. Pass in AppInfo to simplify passing settings to AuthDelegate.
        /// </summary>
        /// <param name="appInfo"></param>
        public Action(ApplicationInfo appInfo)
        {
            this.appInfo = appInfo;

            // Initialize AuthDelegateImplementation using AppInfo. 
            authDelegate = new AuthDelegateImplementation(this.appInfo);

            // Initialize SDK DLLs. If DLLs are missing or wrong type, this will throw an exception

            MIP.Initialize(MipComponent.Policy);

            // This method in AuthDelegateImplementation triggers auth against Graph so that we can get the user ID.
            var id = authDelegate.GetUserIdentity();

            // Create profile.
            profile = CreatePolicyProfile(appInfo, ref authDelegate);

            // Create engine providing Identity from authDelegate to assist with service discovery.
            engine = CreatePolicyEngine(id);
        }

        /// <summary>
        /// Null refs to engine and profile and release all MIP resources.
        /// </summary>
        ~Action()
        {
            engine = null;
            profile = null;
            mipContext = null; 
        }

        /// <summary>
        /// Creates an IFileProfile and returns.
        /// IFileProfile is the root of all MIP SDK File API operations. Typically only one should be created per app.
        /// </summary>
        /// <param name="appInfo"></param>
        /// <param name="authDelegate"></param>
        /// <returns></returns>
        private IPolicyProfile CreatePolicyProfile(ApplicationInfo appInfo, ref AuthDelegateImplementation authDelegate)
        {
            // Initialize MipContext
            mipContext = MIP.CreateMipContext(appInfo, "mip_data", LogLevel.Trace, null, null);

                // Initialize file profile settings to create/use local state.                
                var profileSettings = new PolicyProfileSettings(mipContext, 
                    CacheStorageType.OnDiskEncrypted, 
                    authDelegate);

                // Use MIP.LoadFileProfileAsync() providing settings to create IFileProfile. 
                // IFileProfile is the root of all SDK operations for a given application.
                var profile = Task.Run(async () => await MIP.LoadPolicyProfileAsync(profileSettings)).Result;
                return profile;
            
        }

        /// <summary>
        /// Creates a file engine, associating the engine with the specified identity. 
        /// File engines are generally created per-user in an application. 
        /// IFileEngine implements all operations for fetching labels and sensitivity types.
        /// IFileHandlers are added to engines to perform labeling operations.
        /// </summary>
        /// <param name="identity"></param>
        /// <returns></returns>
        private IPolicyEngine CreatePolicyEngine(Identity identity)
        {

            // If the profile hasn't been created, do that first. 
            if (profile == null)
            {
                profile = CreatePolicyProfile(appInfo, ref authDelegate);
            }

            // Create file settings object. Passing in empty string for the first parameter, engine ID, will cause the SDK to generate a GUID.
            // Locale settings are supported and should be provided based on the machine locale, particular for client applications.
            var engineSettings = new PolicyEngineSettings("", "", "en-US")
            {
                // Provide the identity for service discovery.
                Identity = identity
            };

            // Add the IFileEngine to the profile and return.
            var engine = Task.Run(async () => await profile.AddEngineAsync(engineSettings)).Result;
            return engine;
        }
    

        /// <summary>
        /// Method creates a file handler and returns to the caller. 
        /// IFileHandler implements all labeling and protection operations in the File API.        
        /// </summary>
        /// <param name="options">Struct provided to set various options for the handler.</param>
        /// <returns></returns>
        private IPolicyHandler CreatePolicyHandler(ExecutionStateOptions options)
        {
            // Create the handler using options from FileOptions. Assumes that the engine was previously created and stored in private engine object.
            // There's probably a better way to pass/store the engine, but this is a sample ;)
            var handler = engine.CreatePolicyHandler(options.generateAuditEvent);
            return handler;           
        }


        public ReadOnlyCollection<Microsoft.InformationProtection.Policy.Actions.Action> ComputeActions(ExecutionStateOptions options)
        {
            var handler = CreatePolicyHandler(options);
            ExecutionStateImplementation state = new ExecutionStateImplementation(options);

            var actions = handler.ComputeActions(state);

            if(actions.Count == 0 && options.generateAuditEvent)
            {
                handler.NotifyCommittedActions(state);
            }

            return actions;
        }

        public bool ComputeActionLoop(ExecutionStateOptions options)
        {
            ExecutionStateImplementation state = new ExecutionStateImplementation(options);

            var handler = CreatePolicyHandler(options);
            var actions = handler.ComputeActions(state);

            while(actions.Count > 0)
            {
                
                Console.WriteLine("Action Count: {0}", actions.Count);

                foreach(var action in actions)
                {
                    switch(action.ActionType)
                    {
                        case ActionType.Metadata:

                            var derivedMetadataAction = (MetadataAction)action;

                            if(derivedMetadataAction.MetadataToRemove.Count > 0)
                            {
                                Console.WriteLine("*** Action: Remove Metadata.");

                                //Rather than iterate, in the same we just remove it all.
                                options.metadata.Clear();                                
                            }

                            if(derivedMetadataAction.MetadataToAdd.Count > 0)
                            {
                                Console.WriteLine("*** Action: Apply Metadata.");

                                //Iterate through metadata and add to options
                                foreach(var item in derivedMetadataAction.MetadataToAdd)
                                {
                                    options.metadata.Add(item.Key, item.Value);
                                    Console.WriteLine("*** Added: {0} - {1}", item.Key, item.Value);
                                }
                            }

                            break;

                        case ActionType.ProtectByTemplate:

                            var derivedProtectbyTemplateAction = (ProtectByTemplateAction)action;
                            options.templateId = derivedProtectbyTemplateAction.TemplateId;

                            Console.WriteLine("*** Action: Protect by Template: {0}", derivedProtectbyTemplateAction.TemplateId);
                            
                            break;

                        case ActionType.RemoveProtection:

                            var derivedRemoveProtectionAction = (RemoveProtectionAction)action;                            
                            options.templateId = string.Empty;

                            Console.Write("*** Action: Remove Protection.");

                            break;

                        case ActionType.Justify:

                            var derivedJustificationAction = (JustifyAction)action;
                            Console.WriteLine("*** Justification Required!");
                            Console.Write("Provide Justification: ");
                            string justificationMessage = Console.ReadLine();

                            options.isDowngradeJustified = true;
                            options.downgradeJustification = justificationMessage;

                            break;

                        case ActionType.AddContentFooter:
                            
                            

                        // Any other actions must be explicitly defined after this.

                        default:


                            break;
                    }
                }

                state = new ExecutionStateImplementation(options);
                actions = handler.ComputeActions(state);
                Console.WriteLine("*** Remaining Action Count: {0}", actions.Count);
            }
            if(options.generateAuditEvent && actions.Count == 0)
            {
                handler.NotifyCommittedActions(state);
            }
            return true;
        }

        /// <summary>
        /// List all labels from the engine and return in IEnumerable<Label>
        /// </summary>
        /// <returns></returns>
        public IEnumerable<Label> ListLabels()
        {  
                // Get labels from the engine and return.
                // For a user principal, these will be user specific.
                // For a service principal, these may be service specific or global.
                return engine.SensitivityLabels;          
        }         

        public Label GetLabelById(string labelId)
        {
            return engine.GetLabelById(labelId);
        }
    }
}
