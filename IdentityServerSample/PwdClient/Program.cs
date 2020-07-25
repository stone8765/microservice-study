using System;
using System.Threading.Tasks;
using IdentityModel.Client;
using System.Net.Http;

namespace PwdClient
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var httpClient = new HttpClient();

            var discoveryClient = await httpClient.GetDiscoveryDocumentAsync("http://localhost:5000");

            if (discoveryClient.IsError)
            {
                Console.WriteLine(discoveryClient.Error);
            }

            var tokenResponse = await httpClient.RequestPasswordTokenAsync(new PasswordTokenRequest()
            {
                Address = discoveryClient.TokenEndpoint,
                ClientId = "pwd_client",
                ClientSecret = "secret",
                UserName = "stone",
                Password = "123456",
                Scope = "api"
            });

            if (tokenResponse.IsError)
            {
                Console.WriteLine(tokenResponse.Error);
            }
            else
            {
                Console.WriteLine(tokenResponse.Json);
            }

            httpClient.SetBearerToken(tokenResponse.AccessToken);
            var respone = httpClient.GetAsync("http://localhost:5001/weather").Result;
            if (respone.IsSuccessStatusCode)
            {
                Console.WriteLine(respone.Content.ReadAsStringAsync().Result);
            }

            Console.WriteLine("Hello World!");
        }
    }
}
