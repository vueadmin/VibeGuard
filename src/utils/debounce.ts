/**
 * \u9632\u6296\u51fd\u6570
 * @param func \u8981\u9632\u6296\u7684\u51fd\u6570
 * @param wait \u7b49\u5f85\u65f6\u95f4\uff08\u6beb\u79d2\uff09
 * @param immediate \u662f\u5426\u7acb\u5373\u6267\u884c
 */
export function debounce<T extends (...args: any[]) => any>(
    func: T,
    wait: number,
    immediate = false
): (...args: Parameters<T>) => void {
    let timeout: NodeJS.Timeout | null = null;
    let result: any;

    const debounced = function(this: any, ...args: Parameters<T>) {
        const context = this;

        const later = () => {
            timeout = null;
            if (!immediate) {
                result = func.apply(context, args);
            }
        };

        const callNow = immediate && !timeout;

        if (timeout) {
            clearTimeout(timeout);
        }

        timeout = setTimeout(later, wait);

        if (callNow) {
            result = func.apply(context, args);
        }

        return result;
    };

    // \u6dfb\u52a0\u53d6\u6d88\u65b9\u6cd5
    debounced.cancel = () => {
        if (timeout) {
            clearTimeout(timeout);
            timeout = null;
        }
    };

    // \u6dfb\u52a0\u7acb\u5373\u6267\u884c\u65b9\u6cd5
    debounced.flush = () => {
        if (timeout) {
            clearTimeout(timeout);
            func.apply(null, [] as any);
            timeout = null;
        }
    };

    return debounced;
}

/**
 * \u8282\u6d41\u51fd\u6570
 * @param func \u8981\u8282\u6d41\u7684\u51fd\u6570
 * @param limit \u65f6\u95f4\u9650\u5236\uff08\u6beb\u79d2\uff09
 */
export function throttle<T extends (...args: any[]) => any>(
    func: T,
    limit: number
): (...args: Parameters<T>) => void {
    let inThrottle = false;
    let lastResult: any;

    return function(this: any, ...args: Parameters<T>) {
        const context = this;

        if (!inThrottle) {
            lastResult = func.apply(context, args);
            inThrottle = true;

            setTimeout(() => {
                inThrottle = false;
            }, limit);
        }

        return lastResult;
    };
}