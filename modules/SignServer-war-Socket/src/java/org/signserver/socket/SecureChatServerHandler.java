package org.signserver.socket;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.MessageToMessageDecoder;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.concurrent.GlobalEventExecutor;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.signserver.common.*;
import org.signserver.common.util.*;

import java.util.Arrays;
import java.util.UUID;

public class SecureChatServerHandler extends MessageToMessageDecoder<ByteBuf> {

        final ChannelGroup channels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);
        
        private byte[] PREFIX = "CAG360".getBytes();
        private State state = State.READ_LENGTH;
        private int remaining_length;
        private int index;
        private byte[] data_request;
        private String timestamp = UUID.randomUUID().toString();

        enum State {

            READ_DATA,
            READ_LENGTH,
            READ_DONE
        }

        @Override
        public void channelActive(final ChannelHandlerContext ctx) throws Exception {
            System.out.println("Client connected");
            channels.add(ctx.channel());
            super.channelActive(ctx);
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            System.out.println("Client disconnected");
            SessionManager.getInstance().removeSession(timestamp);
	        DBConnector.getInstances().SocketSetStatusRequest(timestamp);
            super.channelInactive(ctx);
        }

        @Override
        protected void decode(ChannelHandlerContext ctx, ByteBuf i, List<Object> list) throws Exception {
        	//System.out.println("decode");
            byte[] requestData = new byte[i.readableBytes()];
            i.readBytes(requestData);
            //System.out.println(new String(requestData));
            //System.out.println("Data: " + DatatypeConverter.printHexBinary(requestData));
            
            byte[] prefix = new byte[6];
            System.arraycopy(requestData, 0, prefix, 0, 6);
            if (Arrays.equals(prefix, PREFIX)) {
                state = State.READ_LENGTH;
            } else {
                state = State.READ_DATA;
            }
            switch (state) {
                case READ_LENGTH: {
                    //System.out.println("READ_LENGTH...\n\n\n");
                    byte[] length = new byte[4];
                    System.arraycopy(requestData, prefix.length, length, 0, 4);
                    int length_request = Utils.byteArrayToInt(length);
                    //System.out.println("Lncoming message length: " + length_request);
                    data_request = new byte[length_request];
                    System.arraycopy(requestData, 10, data_request, 0, requestData.length - 10);
                    remaining_length = length_request - (requestData.length - 10);
                    index = requestData.length - 10;
                }
                break;
                case READ_DATA: {
                    //System.out.println("READ_DATA...\n\n\n");
                    System.arraycopy(requestData, 0, data_request, index, requestData.length);
                    remaining_length = remaining_length - requestData.length;
                    index = index + requestData.length;
                    if (remaining_length <= 0) {
                        //System.out.println("Length data received: " + data_request.length);
                        
                        String ip = ctx.channel().remoteAddress().toString();
                        Session mSession = new Session(timestamp, ip, ctx);
                        SessionManager.getInstance().setSession(timestamp, mSession);
                        DBConnector.getInstances().Socket_InsertRequest(data_request, timestamp, ip);
                        //System.out.println("ClientIP: "+ip);
                        //System.out.println("Session: "+timestamp);
                        System.out.println("Data received: " + data_request.length + " byte(s)");
                    }
                }
                break;
            }
        }
    }