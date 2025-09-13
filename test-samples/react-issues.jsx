import React, { useEffect, useState } from 'react';

function DangerousComponent() {
    const [data, setData] = useState([]);
    
    // 1. dangerouslySetInnerHTML - XSS 风险
    const renderHTML = (html) => {
        return <div dangerouslySetInnerHTML={{ __html: html }} />;
    };
    
    // 2. useEffect 缺少依赖数组 - 无限循环
    useEffect(() => {
        fetchData();
    }); // 缺少依赖数组！
    
    // 3. 直接操作 DOM
    const updateTitle = () => {
        document.getElementById('title').innerText = 'New Title'; // 违反 React 原则
    };
    
    // 4. 内存泄漏 - 未清理事件监听器
    useEffect(() => {
        window.addEventListener('scroll', handleScroll);
        // 缺少清理函数！
    }, []);
    
    // 5. 数组索引作为 key
    const renderList = () => {
        return data.map((item, index) => (
            <li key={index}>{item.name}</li> // 使用索引作为 key
        ));
    };
    
    // 6. 在条件语句中使用 Hook
    if (data.length > 0) {
        useEffect(() => { // 违反 Hook 规则！
            console.log('Data loaded');
        }, []);
    }
    
    return (
        <div>
            {renderHTML(userContent)}
            {renderList()}
        </div>
    );
}

export default DangerousComponent;