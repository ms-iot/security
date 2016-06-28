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
using Microsoft.Azure.Devices;

namespace MSAAuthenticator
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    AzureAccount azureAccount = new AzureAccount();
                    azureAccount.Type = AzureAccount.AccountType.User;

                    var environment = AzureEnvironment.PublicEnvironments["AzureCloud"];

                    var auth = new Authenticator(AzureRmProfileProvider.Instance.Profile);
                    auth.Login(azureAccount, environment);
                }
                else if (args.Length == 2)
                {
                    var subcriptionId = args[0];
                    var authToken = args[1];

                    Authenticator.ShowIoTHubsInSubscription(subcriptionId, authToken).Wait();
                }
                else
                {
                    Console.WriteLine("Usage:");
                    Console.WriteLine("MSAAuthenticator.exe");
                    Console.WriteLine("    Pop up a credentials gatheting windows and list all IoT Hubs under all subscriptions associated with the user");
                    Console.WriteLine("MSAAuthenticator.exe <subscription_id> <access_token>");
                    Console.WriteLine("    Lists IoT Hubs abd devices given subscription_id and access_token");
                }
            }
            catch (Exception ex)
            {
                var aggr = ex as System.AggregateException;
                if (aggr != null)
                {
                    foreach (var inner in aggr.InnerExceptions)
                    {
                        Console.WriteLine("Exception: {0}", inner.Message);
                    }
                }
                else
                {
                    Console.WriteLine("Exception: {0}", ex.Message);
                }
            }
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

                ShowIoTHubsInSubscription(subscription.Id.ToString(), authtokens[i]).Wait();
            }
        }

        private IEnumerable<AzureTenant> ListAccountTenants(AzureAccount account, AzureEnvironment environment, ShowDialog promptBehavior)
        {
            var commonTenantToken = AcquireAccessToken(account, environment, AuthenticationFactory.CommonAdTenant, promptBehavior);

            using (var subscriptionClient = AzureSession.ClientFactory.CreateCustomClient<SubscriptionClient>(
                new TokenCloudCredentials(commonTenantToken.AccessToken),
                environment.GetEndpointAsUri(AzureEnvironment.Endpoint.ResourceManager)))
            {
                return subscriptionClient.Tenants.List().TenantIds.Select
                    (_ => new AzureTenant { Id = new Guid(_.TenantId), Domain = commonTenantToken.GetDomain() });
            }
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

        private const string IoTHubApiVersion = "2016-02-03";

        public static async Task ShowIoTHubsInSubscription(string subscriptionId, string authorization)
        {
            string relativeUrl = string.Format(CultureInfo.InvariantCulture,
                                               "subscriptions/{0}/providers/Microsoft.Devices/IotHubs?api-version={1}",
                                               subscriptionId,
                                               IoTHubApiVersion);

            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri("https://management.azure.com");

            var message = new HttpRequestMessage(HttpMethod.Get, relativeUrl);

            message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authorization);

            message.Headers.AcceptLanguage.TryParseAdd("en-US");
            message.Headers.Add("x-ms-version", "2013-11-01");
            message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = client.SendAsync(message).Result;

            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                var str = await response.Content.ReadAsStringAsync();

                JObject o = JObject.Parse(str);
                var hubList = o["value"];

                foreach (var hub in hubList)
                {
                    var name = hub["name"].ToString();
                    var location = hub["location"].ToString();
                    var resourcegroup = hub["resourcegroup"].ToString();
                    var hubUri = hub["properties"]["hostName"].ToString();

                    Console.WriteLine("  IoT Hub:");
                    Console.WriteLine("    name          : {0}", name);
                    Console.WriteLine("    location      : {0}", location);
                    Console.WriteLine("    resourcegroup : {0}", resourcegroup);

                    string primaryKey = await GetPrimaryKeyAsync(client, subscriptionId, authorization, resourcegroup, name);

                    await ShowDevicesInHub(hubUri, primaryKey);
                }
            }
            else
            {
                throw new ApplicationException(string.Format("HTTP response is '{0}'", response.StatusCode));
            }
        }

        private static async Task<string> GetPrimaryKeyAsync(HttpClient client, string subscriptionId, string authorization, string resourceGroup, string hubName)
        {
            string relativeUrl = string.Format(CultureInfo.InvariantCulture,
                                   "subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Devices/IotHubs/{2}/IoTHubKeys/listKeys?api-version={3}",
                                   subscriptionId,
                                   Uri.EscapeDataString(resourceGroup),
                                   Uri.EscapeDataString(hubName),
                                   IoTHubApiVersion);

            var message = new HttpRequestMessage(HttpMethod.Post, relativeUrl);

            message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authorization);

            message.Headers.AcceptLanguage.TryParseAdd("en-US");
            message.Headers.Add("x-ms-version", "2013-11-01");
            message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await client.SendAsync(message);
            var str = await response.Content.ReadAsStringAsync();
            JObject o = JObject.Parse(str);

            var keys = o["value"];

            var primaryKey = keys.First(_ => _["keyName"].ToString() == "iothubowner")["primaryKey"].ToString();

            return primaryKey;
        }

        private async static Task ShowDevicesInHub(string ioTHubUri, string primaryKey)
        {
            var connectionString = string.Format(CultureInfo.InvariantCulture,
                "HostName={0};SharedAccessKeyName=iothubowner;SharedAccessKey={1}",
                ioTHubUri, primaryKey);

            var registryManager = RegistryManager.CreateFromConnectionString(connectionString);
            var devices = await registryManager.GetDevicesAsync(1000);
            Console.WriteLine("    Devices:");
            foreach (var device in devices)
            {
                Console.WriteLine("      name          : {0}", device.Id);
            }
        }

    }
}
