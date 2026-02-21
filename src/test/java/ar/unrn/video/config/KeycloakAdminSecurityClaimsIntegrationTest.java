package ar.unrn.video.config;

import ar.unrn.video.rest.TestResource;
import ar.unrn.video.service.TestService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = TestResource.class)
@Import(SecurityConfiguration.class)
class KeycloakAdminSecurityClaimsIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TestService testService;

    @MockBean
    private JwtDecoder jwtDecoder;

    @Test
    @DisplayName("admin endpoint sin autenticacion retorna401")
    void adminEndpoint_sinAutenticacion_retorna401() throws Exception {
        // Setup: Preparar el escenario

        // Ejercitación: Ejecutar la acción a probar
        mockMvc.perform(post("/tests")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Nuevo Test\"}"))
                // Verificación: Verificar el resultado esperado
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("admin endpoint token sin roles retorna403")
    void adminEndpoint_tokenSinRoles_retorna403() throws Exception {
        // Setup: Preparar el escenario
        when(jwtDecoder.decode(anyString())).thenReturn(jwtSinRoles());

        // Ejercitación: Ejecutar la acción a probar
        mockMvc.perform(post("/tests")
                .header("Authorization", "Bearer token-sin-roles")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Nuevo Test\"}"))
                // Verificación: Verificar el resultado esperado
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("admin endpoint realm role admin retorna201")
    void adminEndpoint_realmRoleAdmin_retorna201() throws Exception {
        // Setup: Preparar el escenario
        when(jwtDecoder.decode(anyString())).thenReturn(jwtConRealmRoleAdmin());
        when(testService.create(any())).thenReturn(1L);

        // Ejercitación: Ejecutar la acción a probar
        mockMvc.perform(post("/tests")
                .header("Authorization", "Bearer token-realm-admin")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Nuevo Test\"}"))
                // Verificación: Verificar el resultado esperado
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("admin endpoint resource access admin con azp retorna201")
    void adminEndpoint_resourceAccessAdminConAzp_retorna201() throws Exception {
        // Setup: Preparar el escenario
        when(jwtDecoder.decode(anyString())).thenReturn(jwtConResourceRoleAdmin());
        when(testService.create(any())).thenReturn(1L);

        // Ejercitación: Ejecutar la acción a probar
        mockMvc.perform(post("/tests")
                .header("Authorization", "Bearer token-resource-admin")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Nuevo Test\"}"))
                // Verificación: Verificar el resultado esperado
                .andExpect(status().isCreated());
    }

    private Jwt jwtSinRoles() {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("sub", "user-1")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }

    private Jwt jwtConRealmRoleAdmin() {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("sub", "user-1")
                .claim("realm_access", Map.of("roles", List.of("admin")))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }

    private Jwt jwtConResourceRoleAdmin() {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("sub", "user-1")
                .claim("azp", "web")
                .claim("resource_access", Map.of("web", Map.of("roles", List.of("admin"))))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }
}
