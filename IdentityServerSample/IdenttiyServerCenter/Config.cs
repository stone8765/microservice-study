using System.Collections;
using System.Collections.Generic;
using IdentityServer4.Models;
using IdentityServer4.Test;

namespace IdenttiyServerCenter
{
    public class Config
    {

        public static IEnumerable<ApiScope> GetScopes()
        {
            return new List<ApiScope>
            {
                new ApiScope("api", "My Api")
            };
        }

        public static IEnumerable<ApiResource> GetResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("api", "My Api") // 默认resource会设置到和他一样名字的scope中
                {
                    Scopes = { "api" }
                }
            };
        }

        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client()
                {
                    ClientId="client",
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets = {
                        new Secret("secret".Sha256())
                    },
                    AllowedScopes = {"api"}
                },
                new Client()
                {
                    ClientId = "pwd_client",
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                    ClientSecrets = {
                        new Secret("secret".Sha256())
                    },
                    AllowedScopes = {"api"}
                }
            };
        }

        public static List<TestUser> GetTestUsers()
        {
            return new List<TestUser>
            {
                new TestUser
                {
                    SubjectId = "lst",
                    Username = "stone",
                    Password = "123456"
                }

            };
        }
    }

}