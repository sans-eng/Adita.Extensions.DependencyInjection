//MIT License

//Copyright (c) 2022 Adita

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

using Adita.Identity.Core.Builders;
using Adita.Identity.Core.Models;
using Adita.Identity.Core.Options;
using Adita.Identity.Core.Services;
using Adita.Identity.Core.Services.Factories.ApplicationPrincipalFactories;
using Adita.Identity.Core.Services.LookupNormalizers;
using Adita.Identity.Core.Services.Managers.RoleManagers;
using Adita.Identity.Core.Services.Managers.SignInManagers;
using Adita.Identity.Core.Services.Managers.UserManagers;
using Adita.Identity.Core.Services.PasswordHashers;
using Adita.Identity.Core.Services.PasswordValidators;
using Adita.Identity.Core.Services.Repositories.RoleClaimRepositories;
using Adita.Identity.Core.Services.Repositories.RoleRepositories;
using Adita.Identity.Core.Services.Repositories.UserClaimRepositories;
using Adita.Identity.Core.Services.Repositories.UserRepositories;
using Adita.Identity.Core.Services.Repositories.UserRoleRepositories;
using Adita.Identity.Core.Services.RoleValidators;
using Adita.Identity.Core.Services.UserValidators;
using Adita.Identity.EntityFrameworkCore.Services.Repositories.RoleClaimRepositories;
using Adita.Identity.EntityFrameworkCore.Services.Repositories.RoleRepositories;
using Adita.Identity.EntityFrameworkCore.Services.Repositories.UserClaimRepositories;
using Adita.Identity.EntityFrameworkCore.Services.Repositories.UserRepositories;
using Adita.Identity.EntityFrameworkCore.Services.Repositories.UserRoleRepositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Adita.Extensions.DependencyInjection.Identity
{
    /// <summary>
    /// Contains extension methods to <see cref="IServiceCollection"/> for configuring identity services.
    /// </summary>
    public static class IdentityServiceCollectionExtensions
    {
        #region Public methods
        /// <summary>
        /// Adds and configures the default identity system.
        /// </summary>
        /// <param name="serviceDescriptors">The services available in the application.</param>
        /// <param name="setupAction">An action to configure the <see cref="IdentityOptions"/>.</param>
        /// <returns>An <see cref="IdentityBuilder{TKey, TUser, TUserClaim, TUserRole, TRole, TRoleClaim}"/> for creating and configuring the identity system.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="serviceDescriptors"/> or <paramref name="setupAction"/> is <c>null</c>.</exception>
        public static IdentityBuilder<Guid, IdentityUser, IdentityUserClaim, IdentityUserRole, IdentityRole, IdentityRoleClaim>
            AddDefaultIdentity(this IServiceCollection serviceDescriptors, Action<IdentityOptions> setupAction)
        {
            if (serviceDescriptors is null)
            {
                throw new ArgumentNullException(nameof(serviceDescriptors));
            }

            if (setupAction is null)
            {
                throw new ArgumentNullException(nameof(setupAction));
            }

            return AddIdentity<Guid, IdentityUser, IdentityUserClaim, IdentityUserRole, IdentityRole, IdentityRoleClaim>(serviceDescriptors, setupAction);
        }

        /// <summary>
        /// Adds and configures the identity system.
        /// </summary>
        /// <typeparam name="TKey">The type used for the primary key of the users and roles.</typeparam>
        /// <typeparam name="TUser">The type for the users.</typeparam>
        /// <typeparam name="TRole">The type for the roles.</typeparam>
        /// <param name="serviceDescriptors">The services available in the application.</param>
        /// <param name="setupAction">An action to configure the <see cref="IdentityOptions"/>.</param>
        /// <returns>An <see cref="IdentityBuilder{TKey, TUser, TUserClaim, TUserRole, TRole, TRoleClaim}"/> for creating and configuring the identity system.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="serviceDescriptors"/> or <paramref name="setupAction"/> is <c>null</c>.</exception>
        public static IdentityBuilder<TKey, TUser, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, TRole, IdentityRoleClaim<TKey>>
            AddIdentity<TKey, TUser, TRole>(this IServiceCollection serviceDescriptors, Action<IdentityOptions> setupAction)
            where TKey : IEquatable<TKey>, new()
            where TUser : IdentityUser<TKey>, new()
            where TRole : IdentityRole<TKey>, new()
        {
            if (serviceDescriptors is null)
            {
                throw new ArgumentNullException(nameof(serviceDescriptors));
            }

            if (setupAction is null)
            {
                throw new ArgumentNullException(nameof(setupAction));
            }

            return AddIdentity<TKey, TUser, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, TRole, IdentityRoleClaim<TKey>>(serviceDescriptors, setupAction);
        }

        /// <summary>
        /// Adds and configures the identity system.
        /// </summary>
        /// <typeparam name="TKey">The type used for the primary key of the users and roles.</typeparam>
        /// <typeparam name="TUser">The type for the users.</typeparam>
        /// <param name="serviceDescriptors">The services available in the application.</param>
        /// <param name="setupAction">An action to configure the <see cref="IdentityOptions"/>.</param>
        /// <returns>An <see cref="IdentityBuilder{TKey, TUser, TUserClaim, TUserRole, TRole, TRoleClaim}"/> for creating and configuring the identity system.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="serviceDescriptors"/> or <paramref name="setupAction"/> is <c>null</c>.</exception>

        public static IdentityBuilder<TKey, TUser, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityRole<TKey>, IdentityRoleClaim<TKey>>
            AddIdentity<TKey, TUser>(this IServiceCollection serviceDescriptors, Action<IdentityOptions> setupAction)
            where TKey : IEquatable<TKey>
            where TUser : IdentityUser<TKey>, new()
        {
            if (serviceDescriptors is null)
            {
                throw new ArgumentNullException(nameof(serviceDescriptors));
            }

            if (setupAction is null)
            {
                throw new ArgumentNullException(nameof(setupAction));
            }

            return AddIdentity<TKey, TUser, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityRole<TKey>, IdentityRoleClaim<TKey>>(serviceDescriptors, setupAction);
        }

        /// <summary>
        /// Adds and configures the identity system.
        /// </summary>
        /// <typeparam name="TKey">The type used for the primary key of the users, user claims, user roles, roles and role claims.</typeparam>
        /// <typeparam name="TUser">The type for the users.</typeparam>
        /// <typeparam name="TUserClaim">The type for the user claims.</typeparam>
        /// <typeparam name="TUserRole">The type for the user roles.</typeparam>
        /// <typeparam name="TRole">The type for the roles.</typeparam>
        /// <typeparam name="TRoleClaim">The type for the role claims.</typeparam>
        /// <param name="serviceDescriptors">The services available in the application.</param>
        /// <param name="setupAction">An action to configure the <see cref="IdentityOptions"/>.</param>
        /// <returns>An <see cref="IdentityBuilder{TKey, TUser, TUserClaim, TUserRole, TRole, TRoleClaim}"/> for creating and configuring the identity system.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="serviceDescriptors"/> or <paramref name="setupAction"/> is <c>null</c>.</exception>
        public static IdentityBuilder<TKey, TUser, TUserClaim, TUserRole, TRole, TRoleClaim>
            AddIdentity<TKey, TUser, TUserClaim, TUserRole, TRole, TRoleClaim>
            (this IServiceCollection serviceDescriptors, Action<IdentityOptions> setupAction)
            where TKey : IEquatable<TKey>
            where TUser : IdentityUser<TKey>, new()
            where TUserClaim : IdentityUserClaim<TKey>, new()
            where TUserRole : IdentityUserRole<TKey>, new()
            where TRole : IdentityRole<TKey>, new()
            where TRoleClaim : IdentityRoleClaim<TKey>, new()
        {
            if (serviceDescriptors is null)
            {
                throw new ArgumentNullException(nameof(serviceDescriptors));
            }

            if (setupAction is null)
            {
                throw new ArgumentNullException(nameof(setupAction));
            }

            IdentityBuilder<TKey, TUser, TUserClaim, TUserRole, TRole, TRoleClaim> builder =
                new(serviceDescriptors);

            builder.AddUserValidator<UserValidator<TKey, TUser>>()
                            .AddApplicationPrincipalFactory<ApplicationPrincipalFactory<TKey, TUser, TRole>>()
                            .AddErrorDescriber<IdentityErrorDescriber>()
                            .AddPasswordHasher<BCryptPasswordHasher<TKey, TUser>>()
                            .AddPasswordValidator<PasswordValidator>()
                            .AddUserManager<UserManager<TKey, TUser, TUserClaim, TUserRole, TRole>>()
                            .AddRoleValidator<RoleValidator<TKey, TRole>>()
                            .AddRoleManager<RoleManager<TKey, TRole, TRoleClaim>>()
                            .AddSignInManager<SignInManager<TKey, TUser, TRole>>()
                            .AddLookupNormalizer<UpperInvariantLookupNormalizer>()
                            .ConfigureIdentityOptions(setupAction);

            AddRepositories<TKey, TUser, TUserClaim, TUserRole, TRole, TRoleClaim>(builder.Services);

            return builder;
        }
        #endregion Public methods

        #region Private methods
        private static void AddRepositories<TKey, TUser, TUserClaim, TUserRole, TRole, TRoleClaim>
            (this IServiceCollection serviceDescriptors)
            where TKey : IEquatable<TKey>
            where TUser : IdentityUser<TKey>, new()
            where TUserClaim : IdentityUserClaim<TKey>, new()
            where TUserRole : IdentityUserRole<TKey>, new()
            where TRole : IdentityRole<TKey>, new()
            where TRoleClaim : IdentityRoleClaim<TKey>, new()
        {
            serviceDescriptors.TryAddScoped<IUserRepository<TKey, TUser>, UserRepository<TKey, TUser>>();
            serviceDescriptors.TryAddScoped<IUserClaimRepository<TKey, TUserClaim>, UserClaimRepository<TKey, TUserClaim>>();
            serviceDescriptors.TryAddScoped<IUserRoleRepository<TKey, TUserRole>, UserRoleRepository<TKey, TUserRole>>();
            serviceDescriptors.TryAddScoped<IRoleRepository<TKey, TRole>, RoleRepository<TKey, TRole>>();
            serviceDescriptors.TryAddScoped<IRoleClaimRepository<TKey, TRoleClaim>, RoleClaimRepository<TKey, TRoleClaim>>();
        }
        #endregion Private methods
    }
}
