package com.axcent.DGPRGateway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthGatewayFilter implements GlobalFilter {

    private final JwtUtil jwtUtil;

    // Rotte pubbliche che non richiedono autenticazione
    private static final List<String> PUBLIC_PATHS = List.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/refresh",
            "/api/anagrafica"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();

        // 🔓 Escludi path pubblici (login, register, ecc.)
        if (PUBLIC_PATHS.stream().anyMatch(path::startsWith)) {
            System.out.println("🔓 Accesso pubblico consentito a: " + path);
            return chain.filter(exchange);
        }

        System.out.println("🔐 Richiesta protetta in arrivo: " + path);

        // 🔐 Controllo Authorization Header
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            System.out.println("❌ Token mancante o formato errato");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7); // Rimuove "Bearer "

        if (!jwtUtil.validateToken(token)) {
            System.out.println("❌ Token non valido");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        System.out.println("✅ Token valido, accesso consentito a: " + path);
        return chain.filter(exchange);
    }
}
