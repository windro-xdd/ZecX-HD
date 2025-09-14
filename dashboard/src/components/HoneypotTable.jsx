import React, { useEffect, useState } from 'react';
import { getHoneypotData } from '../services/firestore';

const HoneypotTable = () => {
    const [honeypotData, setHoneypotData] = useState([]);

    useEffect(() => {
        const fetchData = async () => {
            const data = await getHoneypotData();
            setHoneypotData(data);
        };

        fetchData();
    }, []);

    return (
        <div>
            <h2>Live Attack Feed</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Timestamp</th>
                        <th>Source IP</th>
                        <th>Service</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {honeypotData.map((entry) => (
                        <tr key={entry.id}>
                            <td>{entry.id}</td>
                            <td>{new Date(entry.timestamp).toLocaleString()}</td>
                            <td>{entry.sourceIP}</td>
                            <td>{entry.service}</td>
                            <td>{entry.action}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default HoneypotTable;