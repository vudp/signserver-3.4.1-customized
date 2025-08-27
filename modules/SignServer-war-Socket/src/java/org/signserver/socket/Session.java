package org.signserver.socket;

import io.netty.channel.ChannelHandlerContext;

public class Session {
    private String timeStamp;
    private String ip;
    private ChannelHandlerContext context;

    public Session(String timeStamp, String ip, ChannelHandlerContext context) {
        this.timeStamp = timeStamp;
        this.ip = ip;
        this.context = context;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public ChannelHandlerContext getContext() {
        return context;
    }

    public void setContext(ChannelHandlerContext context) {
        this.context = context;
    }
}