# Identityframework-Iam

Extends rather static .NET IdentityFramework Policies of fine grained IAM rules for better and more dynamic Authorization handling.

## Purpose

As you may know, the new Identity framework pushes for the use of policies as the solve-it-all security concept. The policies are really great and I personally like them. What I don't like is that they are somewhat static by nature. 

Let's image we would have a simple endpoint ```GET api/v1/values``` which we would like to fortify with some kind of authorization.

With policies, we could do something like this:
```cs
[HttpGet]
[Authorize(Policy = "Values:GetList")]
public ActionResult<IEnumerable<string>> Get()
```

And to restrict the access to *Get* endpoint to users under role *Viewer* and *Editor* and *Admin* we would do this:
```cs
services.AddAuthorization(options =>
    {
        options.AddPolicy("Values:GetList", policy =>
            {
                policy.RequireAuthenticatedRole(new string[] { "Viewer", "Editor", "Admin" });
            });
    });
```

This is done in our beloved *Startup.cs* and it is done while coding the security rules. So when you decide to change which roles are authorized for the policy, you need to go into your code and change it.

I wanted to change it and introduce a more refined Identity Access Management system which would allow the following:
+ see policies as permissions ({resource}:{operation})
+ dynamically attach roles to permissions/policies
+ allow to attach permission/policy to a specific user without the user being in some role

I must admit I took an inspiration in AWS IAM which I use daily.

I also wanted to overcome the biggest Identity framework limitation (IMHO) which is the lack of default support for multi-tenancy applications.

With the IdentityFramework.Iam, you can achieve following in the multi-tenant scenarios:
+ one user account can have different roles in different tenants
+ roles can have different permissions/policies in different tenants
+ allow to attach permission/policy to a specific user for a specific tenant without the user being in some role

## Usage

The basic usage is pretty simple. It all revolves around concept of *IamProvider* which enables you to create the mappings between permissions to your resources and the roles allowed to access them. You have two choices when it comes to IAM.

### Simple

Add the needed dependencies with the following line.
```cs
services.AddIamCore();
```

Implement the *IIamProvider* interface using either EF, WCF or something totally different and register it with:
```cs
services.AddSingleton<IIamProvider, YourIamProvider>();
```

You can see that the *IIamProvider* accepts a *IIamProviderCache* in every method. This is by design because I wanted to emphasize the importance of caching so I thought it would be a good idea to force the caching into the design. When implementing *IIamProvider*, you should always use the cache.

The default cache is implemented as a simple ConcurrentDictionary cache. If you would like to use some more advanced cache (Redis or MemoryCache for example), you can implement the *IIamProviderCache* interface and use the 
```cs
services.AddIamCore(options => options.UseDefaultCache = false);
services.AddSingleton<IIamProviderCache, YourIamProviderCache>();
```

### Multi-tenant enabled

Add the needed dependencies with the following line.
```cs
services.AddMultiTenantIamCore<T>();
```
Where *T* is the type of your tenant id (Guid, long etc.)

Implement the *IMultiTenantIamProvider<T>* interface using either EF, WCF or something totally different and register it with:
```cs
services.AddSingleton<typeof(IMultiTenantIamProvider<T>), YourMtIamProvider>();
```

You can see that the *IMultiTenantIamProvider<T>* accepts a *IMultiTenantIamProviderCache<T>* in every method. This is by design because I wanted to emphasize the importance of caching so I thought it would be a good idea to force the caching into the design. When implementing *IMultiTenantIamProvider<T>*, you should always use the cache.

The default cache is implemented as a simple ConcurrentDictionary cache. If you would like to use some more advanced cache (Redis or MemoryCache for example), you can implement the *IMultiTenantIamProviderCache<T>* interface and use the 
```cs
services.AddMultiTenantIamCore<long>(options => options.IamOptions.UseDefaultCache = false);
services.AddSingleton<typeof(IMultiTenantIamProviderCache<T>), YourMtIamProviderCache>();
```

The multi-tenant version of IAM is specific with few more things.

#### Tenant provider
Tenant provider is a class which supplies the current tenant id to the IAM custom policy provider. It should implement the *ITenantProvider<T>* interface which has only one method.

The framework comes with a default implementation of the tenant provider which tries to get the tenant from a custom header. The name of the custom header is customizable and it is *X-TenantId* by default. When you would desire to change it, do this:

```cs
services.AddMultiTenantIamCore<long>(options => options.IamTenantProviderOptions.HeaderName = "X-YourCustomHeader");
```

If the implementation is not sufficient or you would like to change the behavior, just implement the *ITenantProvider<T>* interface and use this:

```cs
services.AddMultiTenantIamCore<long>(options => options.IamTenantProviderOptions.UseDefaultTenantProvider = false);
services.AddSingleton<typeof(ITenantProvider<T>), YourTenantProvider>();
```

#### Multi-tenant Role store

In order to enable the multi-tenancy I had to design a custom *IUserRoleStore* in a form of *IMultiTenantUserRoleStore<TUser, Tkey>* interface where *TUser* is the type of your identity user and *TKey* is type of the tenant id. This role store copies the methods of the original inteface adding the tenant id parameter. You need to implement this interface and add it via:

```cs
services.AddScoped<typeof(IMultiTenantUserRoleStore<TUser, Tkey>), YourRoleStore>();
```

#### Multi-tenant Claim store

In order to enable the multi-tenancy I had to design also custom *IUserClaimStore* in a form of *IMultiTenantUserClaimStore<TUser, Tkey>*. This claim store copies the methods of the original inteface adding the tenant id parameter. You need to implement this interface and add it via:

```cs
services.AddScoped<typeof(IMultiTenantUserClaimStore<TUser, Tkey>), YourClaimStore>();
```

Both custom stores are used by *UserManager* extensions which follow the non-multi-tenant ones.

### Extensions

The framework comes loaded with extensions to UserManager and ClaimsIdentity.

#### UserManager

+ Policy handling
..+ AttachPolicy(ies) - attaches a permission(s) to a specific user, granting an access to perform a specific action
..+ DetachPolicy(ies) - dettaches permission(s) from a specific user, denying an access to perform a specific action
..+ GetAttachedPolicies - gets permissions to operations user can perform
..+ GetUsersAttachedToPolicies - gets users attached to specific permissions

Of course the multi-tenant extensions for *UserManager* allow you to do the same for specific tenant id. This applies also to user to role handling.

+ AddToRole(s)
+ RemoveFromRole(s)
+ IsInRole
+ GetRoles
+ GetUsersInRoles

These methods can be used to manage the mapping between *User* and *Role*(s) or *Permission*(s).

### ClaimsIdentity

+ AddIamClaims - adds claims to the Identity to be used for token/cookie generation

This extensions is suggested to be used when generation Bearer token for example:

```cs
 public ClaimsIdentity GenerateClaimsIdentity(User user, IList<string> roles, IList<Claim> claims)
{
    Claim[] _claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.UserName),
    };

    ClaimsIdentity claimsIdentity = new ClaimsIdentity(_claims, "Token");

    claimsIdentity.AddIamClaims(roles, claims);

    return claimsIdentity;
}
```

Which is then used:

```cs
 public static async Task<JwtToken> GenerateJwt(this ClaimsIdentity identity, IJwtFactory jwtFactory, JwtIssuerOptions jwtOptions, long id)
{
    var ret = new JwtToken()
    {
        Id = id.ToString(),
        Token = await jwtFactory.GenerateEncodedToken(id, identity),
        ExpiresIn = (int)jwtOptions.ValidFor.TotalSeconds
    };

    return ret;
}
```

For the multi-tenant variant it is a little bit more complicated and you need to use the two custom stores.

```cs
public ClaimsIdentity GenerateClaimsIdentity<TKey>(User user, IDictionary<TKey, IList<string>> roles, IDictionary<TKey, IList<Claim>> claims)
{
    Claim[] _claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.UserName),
    };

    ClaimsIdentity claimsIdentity = new ClaimsIdentity(_claims, "Token");

    claimsIdentity.AddIamClaims(roles, claims);

    return claimsIdentity;
}
```

```cs
identity = jwtFactory.GenerateClaimsIdentity(user, await roleStore.GetRolesAsync(user, CancellationToken.None), await claimStore.GetClaimsAsync(user, CancellationToken.None));
```