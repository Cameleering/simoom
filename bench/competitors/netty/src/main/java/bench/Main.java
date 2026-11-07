package bench;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.epoll.*;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.*;

/** Raw Netty: HttpServerCodec and a handler that writes a fixed reply (or echoes POST bodies). */
public final class Main {
    private static final ByteBuf HELLO = Unpooled.unreleasableBuffer(Unpooled.directBuffer().writeBytes("Hello, World!".getBytes()));

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        EventLoopGroup group = new MultiThreadIoEventLoopGroup(EpollIoHandler.newFactory());
        new ServerBootstrap().group(group).channel(EpollServerSocketChannel.class)
            .option(ChannelOption.SO_BACKLOG, 65535).option(EpollChannelOption.SO_REUSEPORT, true)
            .childOption(ChannelOption.TCP_NODELAY, true)
            .childHandler(new ChannelInitializer<SocketChannel>() {
                @Override protected void initChannel(SocketChannel ch) {
                    ch.pipeline().addLast(new HttpServerCodec(), new HttpObjectAggregator(1 << 20), new SimpleChannelInboundHandler<FullHttpRequest>() {
                        @Override protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) {
                            boolean post = req.method() == HttpMethod.POST;
                            ByteBuf body = post ? req.content().retain() : HELLO.duplicate();
                            FullHttpResponse rsp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, body);
                            rsp.headers().set(HttpHeaderNames.CONTENT_TYPE, post ? "application/json" : "text/plain")
                                .setInt(HttpHeaderNames.CONTENT_LENGTH, body.readableBytes());
                            ctx.write(rsp, ctx.voidPromise());
                        }
                        @Override public void channelReadComplete(ChannelHandlerContext ctx) { ctx.flush(); }
                    });
                }
            }).bind(port).sync().channel().closeFuture().sync();
    }
}
