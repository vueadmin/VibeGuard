import { CacheEntry } from '../types';
import { Logger } from '../utils/logger';

export class CacheManager {
    private cache = new Map<string, CacheEntry>();
    private maxSize = 100; // \u6700\u5927\u7f13\u5b58\u6587\u4ef6\u6570
    private ttl = 60000; // 60\u79d2\u8fc7\u671f
    private cleanupInterval: NodeJS.Timeout | null = null;

    constructor() {
        // \u542f\u52a8\u5b9a\u671f\u6e05\u7406
        this.startCleanupTimer();
    }

    /**
     * \u8bbe\u7f6e\u7f13\u5b58
     */
    set(key: string, value: any): void {
        // LRU \u6dd8\u6c70\u7b56\u7565
        if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
            const firstKey = this.cache.keys().next().value;
            if (firstKey) {
                this.cache.delete(firstKey);
                Logger.debug(`\u7f13\u5b58\u6dd8\u6c70: ${firstKey}`);
            }
        }

        this.cache.set(key, {
            value,
            timestamp: Date.now()
        });
    }

    /**
     * \u83b7\u53d6\u7f13\u5b58
     */
    get<T>(key: string): T | null {
        const entry = this.cache.get(key);
        
        if (!entry) {
            return null;
        }
        
        // \u68c0\u67e5\u8fc7\u671f
        if (Date.now() - entry.timestamp > this.ttl) {
            this.cache.delete(key);
            Logger.debug(`\u7f13\u5b58\u8fc7\u671f: ${key}`);
            return null;
        }
        
        // \u66f4\u65b0\u8bbf\u95ee\u65f6\u95f4 (LRU)
        this.cache.delete(key);
        this.cache.set(key, {
            value: entry.value,
            timestamp: Date.now()
        });
        
        return entry.value as T;
    }

    /**
     * \u5220\u9664\u7f13\u5b58
     */
    delete(key: string): boolean {
        return this.cache.delete(key);
    }

    /**
     * \u6e05\u7a7a\u6240\u6709\u7f13\u5b58
     */
    clear(): void {
        this.cache.clear();
        Logger.debug('\u7f13\u5b58\u5df2\u6e05\u7a7a');
    }

    /**
     * \u83b7\u53d6\u7f13\u5b58\u5927\u5c0f
     */
    size(): number {
        return this.cache.size;
    }

    /**
     * \u68c0\u67e5\u662f\u5426\u5b58\u5728\u7f13\u5b58
     */
    has(key: string): boolean {
        const entry = this.cache.get(key);
        if (!entry) {
            return false;
        }
        
        // \u68c0\u67e5\u8fc7\u671f
        if (Date.now() - entry.timestamp > this.ttl) {
            this.cache.delete(key);
            return false;
        }
        
        return true;
    }

    /**
     * \u5f00\u59cb\u5b9a\u671f\u6e05\u7406
     */
    private startCleanupTimer(): void {
        // \u6bcf30\u79d2\u6e05\u7406\u4e00\u6b21\u8fc7\u671f\u7f13\u5b58
        this.cleanupInterval = setInterval(() => {
            this.cleanup();
        }, 30000);
    }

    /**
     * \u6e05\u7406\u8fc7\u671f\u7f13\u5b58
     */
    private cleanup(): void {
        const now = Date.now();
        let cleanedCount = 0;
        
        for (const [key, entry] of this.cache.entries()) {
            if (now - entry.timestamp > this.ttl) {
                this.cache.delete(key);
                cleanedCount++;
            }
        }
        
        if (cleanedCount > 0) {
            Logger.debug(`\u6e05\u7406\u8fc7\u671f\u7f13\u5b58: ${cleanedCount} \u9879`);
        }
    }

    /**
     * \u83b7\u53d6\u7f13\u5b58\u7edf\u8ba1\u4fe1\u606f
     */
    getStats(): {
        size: number;
        maxSize: number;
        hitRate: number;
        ttl: number;
    } {
        return {
            size: this.cache.size,
            maxSize: this.maxSize,
            hitRate: 0, // \u53ef\u4ee5\u6269\u5c55\u5b9e\u73b0\u547d\u4e2d\u7387\u7edf\u8ba1
            ttl: this.ttl
        };
    }

    /**
     * \u91ca\u653e\u8d44\u6e90
     */
    dispose(): void {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
        }
        this.cache.clear();
    }
}