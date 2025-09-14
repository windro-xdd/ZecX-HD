import React, { useEffect, useState } from 'react';
import HoneypotTable from './components/HoneypotTable';
import { fetchHoneypotData } from './services/firestore';

const App = () => {
    const [honeypotData, setHoneypotData] = useState([]);

    useEffect(() => {
        const getData = async () => {
            const data = await fetchHoneypotData();
            setHoneypotData(data);
        };

        getData();
    }, []);

    return (
        <div>
            <h1>ZecX Honeypot Dashboard</h1>
            <HoneypotTable data={honeypotData} />
        </div>
    );
};

export default App;