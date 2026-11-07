package bench;

import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServerOptions;

/** Vert.x core HTTP server, one verticle instance per CPU, native transport preferred. */
public final class Main extends VerticleBase {
    private static final Buffer HELLO = Buffer.buffer("Hello, World!");

    @Override public Future<?> start() {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        return vertx.createHttpServer(new HttpServerOptions().setTcpNoDelay(true).setAcceptBacklog(65535).setReusePort(true))
            .requestHandler(req -> {
                if (req.method() == io.vertx.core.http.HttpMethod.POST) {
                    req.body().onSuccess(b -> req.response().putHeader("content-type", "application/json").end(b));
                } else {
                    req.response().putHeader("content-type", "text/plain").end(HELLO);
                }
            }).listen(port);
    }

    public static void main(String[] args) {
        int n = Runtime.getRuntime().availableProcessors();
        Vertx vertx = Vertx.vertx(new VertxOptions().setPreferNativeTransport(true).setEventLoopPoolSize(n));
        vertx.deployVerticle(Main::new, new DeploymentOptions().setInstances(n));
    }
}
