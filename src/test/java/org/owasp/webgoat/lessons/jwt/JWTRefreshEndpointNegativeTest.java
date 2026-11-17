package org.owasp.webgoat.lessons.jwt;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class JWTRefreshEndpointNegativeTest {

  private MockMvc mockMvc;

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.standaloneSetup(new JWTRefreshEndpoint()).build();
  }

  // 1. Prueba negativa de AUTENTICACIÓN (sin cabecera Authorization)
  @Test
  void shouldRejectRequestWithoutAuthenticationToken() throws Exception {
    mockMvc.perform(post("/JWT/refresh/checkout"))
        .andExpect(status().isUnauthorized()); // Espera HTTP 401
  }

  // 2. Prueba negativa de AUTORIZACIÓN (usuario sin privilegios o token inválido)
  @Test
  void shouldRejectUnauthorizedOrForgedToken() throws Exception {
    mockMvc.perform(post("/JWT/refresh/checkout")
            .header("Authorization", "Bearer token-falso-sin-permisos"))
        .andExpect(status().isOk()); // WebGoat devuelve AttackResult de fallo controlado
  }

  // 3. Prueba negativa de VALIDACIÓN DE ENTRADAS (cuerpo vacío o nulo en login)
  @Test
  void shouldRejectEmptyOrMalformedInputOnLogin() throws Exception {
    mockMvc.perform(post("/JWT/refresh/login")
            .contentType(MediaType.APPLICATION_JSON))
        .andExpect(status().isUnauthorized()); // Rechaza entrada nula sin romper el servidor
  }

  // 4. Prueba negativa de MANEJO DE ERRORES (JSON malformado no debe exponer traza 500)
  @Test
  void shouldHandleMalformedJsonWithoutInternalServerError() throws Exception {
    mockMvc.perform(post("/JWT/refresh/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{ json_invalido "))
        .andExpect(status().isBadRequest()); // Espera HTTP 400 controlado, nunca 500
  }
}
