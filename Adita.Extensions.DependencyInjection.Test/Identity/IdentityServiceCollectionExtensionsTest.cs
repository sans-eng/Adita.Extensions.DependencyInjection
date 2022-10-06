using Adita.Extensions.DependencyInjection.Identity;
using Adita.Extensions.Logging;
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
using Adita.Identity.EntityFrameworkCore.Models.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Adita.Extensions.DependencyInjection.Test.Identity
{
    [TestClass]
    public class IdentityServiceCollectionExtensionsTest
    {
        [TestMethod]
        public void CanUseDefaultIdentity()
        {
            IServiceCollection serviceDescriptors = new ServiceCollection();

            serviceDescriptors.AddDefaultIdentity(o =>
            {
                o.RepositoryOptions.MaxLengthForKeys = 100;
            });

            serviceDescriptors.AddDbContext<DbContext,IdentityDbContext<Guid>>(o =>
                o.UseInMemoryDatabase("IdentityTest")
                .ConfigureWarnings(b => b.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            );

            serviceDescriptors.AddLogging(builder => builder.AddFileLogger(options => options.Directory = "D://Temp"));

            ServiceProvider serviceProvider = serviceDescriptors.BuildServiceProvider();

            IApplicationPrincipalFactory<IdentityUser> applicationPrincipalFactory =
                serviceProvider.GetRequiredService<IApplicationPrincipalFactory<IdentityUser>>();
            Assert.IsNotNull(applicationPrincipalFactory);

            ILookupNormalizer normalizer = serviceProvider.GetRequiredService<ILookupNormalizer>();
            Assert.IsNotNull(normalizer);

            IPasswordHasher<Guid, IdentityUser> passwordHasher = serviceProvider.GetRequiredService<IPasswordHasher<Guid, IdentityUser>>();
            Assert.IsNotNull(passwordHasher);

            IPasswordValidator passwordValidator = serviceProvider.GetRequiredService<IPasswordValidator>();
            Assert.IsNotNull(passwordValidator);

            IRoleValidator<IdentityRole> roleValidator = serviceProvider.GetRequiredService<IRoleValidator<IdentityRole>>();
            Assert.IsNotNull(roleValidator);

            IUserValidator<IdentityUser> userValidator = serviceProvider.GetRequiredService<IUserValidator<IdentityUser>>();
            Assert.IsNotNull(userValidator);

            IdentityErrorDescriber errorDescriber = serviceProvider.GetRequiredService<IdentityErrorDescriber>();
            Assert.IsNotNull(errorDescriber);

            IRoleManager<Guid, IdentityRole> roleManager = serviceProvider.GetRequiredService<IRoleManager<Guid, IdentityRole>>();
            Assert.IsNotNull(roleManager);

            ISignInManager<IdentityUser> signInManager = serviceProvider.GetRequiredService<ISignInManager<IdentityUser>>();
            Assert.IsNotNull(signInManager);

            IUserManager<Guid, IdentityUser, IdentityRole> userManager = serviceProvider.GetRequiredService<IUserManager<Guid, IdentityUser, IdentityRole>>();
            Assert.IsNotNull(userManager);

            IRoleClaimRepository<Guid, IdentityRoleClaim> roleClaimRepository = serviceProvider.GetRequiredService<IRoleClaimRepository<Guid, IdentityRoleClaim>>();
            Assert.IsNotNull(roleClaimRepository);

            IRoleRepository<Guid, IdentityRole> roleRepository = serviceProvider.GetRequiredService<IRoleRepository<Guid, IdentityRole>>();
            Assert.IsNotNull(roleRepository);

            IUserClaimRepository<Guid, IdentityUserClaim> userClaimRepository = serviceProvider.GetRequiredService<IUserClaimRepository<Guid, IdentityUserClaim>>();
            Assert.IsNotNull(userClaimRepository);

            IUserRepository<Guid, IdentityUser> userRepository = serviceProvider.GetRequiredService<IUserRepository<Guid, IdentityUser>>();
            Assert.IsNotNull(userRepository);

            IUserRoleRepository<Guid, IdentityUserRole> userRoleRepository = serviceProvider.GetRequiredService<IUserRoleRepository<Guid, IdentityUserRole>>();
            Assert.IsNotNull(userRoleRepository);

            var identityOptionsSetup = serviceProvider.GetRequiredService<IConfigureOptions<IdentityOptions>>();
            Assert.IsNotNull(identityOptionsSetup);

            var applicationIdentityOptionsGetter = serviceProvider.GetRequiredService<IOptions<ApplicationIdentityOptions>>();
            Assert.IsNotNull(applicationIdentityOptionsGetter);

            var lockoutOptionsGetter = serviceProvider.GetRequiredService<IOptions<LockoutOptions>>();
            Assert.IsNotNull(lockoutOptionsGetter);

            var passwordOptionsGetter = serviceProvider.GetRequiredService<IOptions<PasswordOptions>>();
            Assert.IsNotNull(passwordOptionsGetter);

            var roleOptionsGetter = serviceProvider.GetRequiredService<IOptions<RoleOptions>>();
            Assert.IsNotNull(roleOptionsGetter);

            var userOptionsGetter = serviceProvider.GetRequiredService<IOptions<UserOptions>>();
            Assert.IsNotNull(userOptionsGetter);

            var repositoryOptionsGetter = serviceProvider.GetRequiredService<IOptions<RepositoryOptions>>();
            Assert.IsNotNull(repositoryOptionsGetter);
        }
    }
}
