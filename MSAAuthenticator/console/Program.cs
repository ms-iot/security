using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;

using Hyak.Common;
using Microsoft.Azure;
using Microsoft.Azure.Subscriptions;
using Microsoft.Azure.Commands.ResourceManager.Common;
using Microsoft.Azure.Commands.Common.Authentication;
using Microsoft.Azure.Commands.Common.Authentication.Models;
using Microsoft.Azure.Commands.Profile.Models;
using Microsoft.Azure.Commands.Common.Authentication.Factories;
using Microsoft.Azure.Commands.Common.Authentication.Properties;
using Microsoft.Azure.Commands.Profile;
using Microsoft.Azure.Subscriptions.Models;
using Microsoft.WindowsAzure.Commands.Common;
using System.Management.Automation;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Globalization;
using Newtonsoft.Json.Linq;

namespace MSAAuthenticator
{
    class Program
    {
        static void Main(string[] args)
        {
            AzureAccount azureAccount = new AzureAccount();
            azureAccount.Type = AzureAccount.AccountType.User;

            var environment = AzureEnvironment.PublicEnvironments["AzureCloud"];

            var auth = new Authenticator(AzureRmProfileProvider.Instance.Profile);
            auth.Login(azureAccount, environment);
        }
    }

    class Authenticator
    {
        private AzureRMProfile _profile;

        public Authenticator(AzureRMProfile profile)
        {
            _profile = profile;

            if (_profile != null && _profile.Context != null &&
                _profile.Context.TokenCache != null && _profile.Context.TokenCache.Length > 0)
            {
                TokenCache.DefaultShared.Deserialize(_profile.Context.TokenCache);
            }
        }

        public void Login(
            AzureAccount account,
            AzureEnvironment environment)
        {
            ShowDialog promptBehavior = ShowDialog.Always;

            var tenants = ListAccountTenants(account, environment, promptBehavior).ToArray();

            account.SetProperty(AzureAccount.Property.Tenants, null);
            string accountId = null;

            List<AzureSubscription> azureSubscriptions = new List<AzureSubscription>();
            List<string> authtokens = new List<string>();

            for (int i = 0; i < tenants.Count(); i++)
            {
                var tenant = tenants[i].Id.ToString();

                IAccessToken token = AcquireAccessToken(account, environment, tenant, ShowDialog.Auto);

                if (accountId == null)
                {
                    accountId = account.Id;
                    account.SetOrAppendProperty(AzureAccount.Property.Tenants, tenant);
                }
                else if (accountId.Equals(account.Id, StringComparison.OrdinalIgnoreCase))
                {
                    account.SetOrAppendProperty(AzureAccount.Property.Tenants, tenant);
                }
                else
                {   // if account ID is different from the first tenant account id we need to ignore current tenant
                    Console.WriteLine(string.Format(
                        "Account ID '{0}' for tenant '{1}' does not match home Account ID '{2}'",
                        account.Id,
                        tenant,
                        accountId));
                    account.Id = accountId;
                    token = null;
                }

                int found = TryGetTenantSubscription(token, account, environment, tenant, azureSubscriptions, authtokens);
            }

            for(int i=0; i<azureSubscriptions.Count; ++i)
            {
                var subscription = azureSubscriptions[i];

                Console.WriteLine("Subscription:");
                Console.WriteLine("  Name    = {0}", subscription.Name);
                Console.WriteLine("  Id      = {0}", subscription.Id);
                Console.WriteLine("  State   = {0}", subscription.State);
                Console.WriteLine("  Account = {0}", subscription.Account);

                ShowIoTHubsInSubscription(subscription.Id.ToString(), authtokens[i]);
            }
        }

        private List<AzureTenant> ListAccountTenants(AzureAccount account, AzureEnvironment environment, ShowDialog promptBehavior)
        {
            List<AzureTenant> result = new List<AzureTenant>();
            try
            {
                var commonTenantToken = AcquireAccessToken(account, environment, AuthenticationFactory.CommonAdTenant, promptBehavior);

                using (var subscriptionClient = AzureSession.ClientFactory.CreateCustomClient<SubscriptionClient>(
                    new TokenCloudCredentials(commonTenantToken.AccessToken),
                    environment.GetEndpointAsUri(AzureEnvironment.Endpoint.ResourceManager)))
                {
                    //TODO: Fix subscription client to not require subscriptionId
                    result = MergeTenants(account, subscriptionClient.Tenants.List().TenantIds, commonTenantToken);
                }
            }
            catch
            {
                Console.WriteLine(string.Format("Unable to acquire token for tenant '{0}'", AuthenticationFactory.CommonAdTenant));
            }

            return result;
        }

        private IAccessToken AcquireAccessToken(AzureAccount account,
            AzureEnvironment environment,
            string tenantId,
            ShowDialog promptBehavior)
        {
            if (account.Type == AzureAccount.AccountType.AccessToken)
            {
                tenantId = tenantId ?? AuthenticationFactory.CommonAdTenant;
                return new SimpleAccessToken(account, tenantId);
            }

            return AzureSession.AuthenticationFactory.Authenticate(
                account,
                environment,
                tenantId,
                null,
                promptBehavior,
                TokenCache.DefaultShared);
        }

        private int TryGetTenantSubscription(IAccessToken accessToken,
            AzureAccount account,
            AzureEnvironment environment,
            string tenantId,
            List<AzureSubscription> azureSubscriptions,
            List<string> authtokens)
        {
            using (var subscriptionClient = AzureSession.ClientFactory.CreateCustomClient<SubscriptionClient>(
                new TokenCloudCredentials(accessToken.AccessToken),
                environment.GetEndpointAsUri(AzureEnvironment.Endpoint.ResourceManager)))
            {
                var subscriptions = (subscriptionClient.Subscriptions.List().Subscriptions ??
                                        new List<Microsoft.Azure.Subscriptions.Models.Subscription>())
                                    .Where(s => "enabled".Equals(s.State, StringComparison.OrdinalIgnoreCase) ||
                                                "warned".Equals(s.State, StringComparison.OrdinalIgnoreCase));

                account.SetProperty(AzureAccount.Property.Subscriptions, subscriptions.Select(i => i.SubscriptionId).ToArray());

                foreach (var subscriptionFromServer in subscriptions)
                {
                    var currentSubscription = new AzureSubscription
                    {
                        Id = new Guid(subscriptionFromServer.SubscriptionId),
                        Account = accessToken.UserId,
                        Environment = environment.Name,
                        Name = subscriptionFromServer.DisplayName,
                        State = subscriptionFromServer.State,
                        Properties = new Dictionary<AzureSubscription.Property, string>
                        {
                            { AzureSubscription.Property.Tenants, accessToken.TenantId }
                        }
                    };

                    azureSubscriptions.Add(currentSubscription);
                    authtokens.Add(accessToken.AccessToken);
                }

                return subscriptions.Count();
            }
        }

        public static List<AzureTenant> MergeTenants(
            AzureAccount account,
            IEnumerable<TenantIdDescription> tenants,
            IAccessToken token)
        {
            List<AzureTenant> result = null;
            if (tenants != null)
            {
                var existingTenants = new List<AzureTenant>();
                account.SetProperty(AzureAccount.Property.Tenants, null);
                foreach(var t in tenants)
                {
                    existingTenants.Add(new AzureTenant { Id = new Guid(t.TenantId), Domain = token.GetDomain() });
                    account.SetOrAppendProperty(AzureAccount.Property.Tenants, t.TenantId);
                }

                result = existingTenants;
            }

            return result;
        }

        private const string IoTHubPreviewApiVersion = "2015-08-15-preview";

        public static void ShowIoTHubsInSubscription(string subscriptionId, string authorization)
        {
            string relativeUrl = string.Format(CultureInfo.InvariantCulture,
                                               "subscriptions/{0}/providers/Microsoft.Devices/IoTHubs?api-version={1}",
                                               subscriptionId,
                                               IoTHubPreviewApiVersion);

            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri("https://management.azure.com");

            var message = new HttpRequestMessage(HttpMethod.Get, relativeUrl);

            //message.Headers.Authorization = AuthenticationHeaderValue.Parse(authorization);

            message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authorization);

            message.Headers.AcceptLanguage.TryParseAdd("en-US");
            message.Headers.Add("x-ms-version", "2013-11-01");
            message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = client.SendAsync(message).Result;

            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                var str = response.Content.ReadAsStringAsync().Result;

                JObject o = JObject.Parse(str);
                var hubList = o["value"];

                foreach (var hub in hubList)
                {
                    var name = hub["name"];
                    var location = hub["location"];
                    var resourcegroup = hub["resourcegroup"];

                    Console.WriteLine("  IoT Hub:");
                    Console.WriteLine("    name          : {0}", name);
                    Console.WriteLine("    location      : {0}", location);
                    Console.WriteLine("    resourcegroup : {0}", resourcegroup);
                }
            }
        }

    }
}
