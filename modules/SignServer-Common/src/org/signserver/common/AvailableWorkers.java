/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common;

/**
 *
 * @author PHUONGVU
 */
public class AvailableWorkers {
    String workerName;
    String workerFileConfig;
    
    public AvailableWorkers() {
        this.workerName = null;
        this.workerFileConfig = null;
    }

    public AvailableWorkers(String workerName, String workerFileConfig) {
        this.workerName = workerName;
        this.workerFileConfig = workerFileConfig;
    }

    public String getWorkerName() {
        return workerName;
    }

    public void setWorkerName(String workerName) {
        this.workerName = workerName;
    }

    public String getWorkerFileConfig() {
        return workerFileConfig;
    }

    public void setWorkerFileConfig(String workerFileConfig) {
        this.workerFileConfig = workerFileConfig;
    }
    
    
}
