const DeleteConfirmModal = ({ isOpen, onConfirm, onCancel }) => {
   if (!isOpen) return null;
   
   return (
       <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
           <div className="bg-white p-6 rounded-lg shadow-lg w-96 mx-4">
               <h3 className="text-lg font-bold mb-4">Löschen bestätigen</h3>
               <p className="mb-6">Möchten Sie diesen Eintrag wirklich löschen?</p>
               <div className="flex justify-end space-x-3">
                   <button onClick={onCancel} className="px-4 py-2 bg-gray-200 rounded hover:bg-gray-300">
                       Abbrechen
                   </button>
                   <button onClick={onConfirm} className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700">
                       Löschen
                   </button>
               </div>
           </div>
       </div>
   );
};

const AdminDashboard = () => {
   const [showDeleteConfirm, setShowDeleteConfirm] = React.useState(false);
   const { registrations, stats, csrfToken } = window.ADMIN_DATA;

   return (
       <div className="min-h-screen bg-gray-50 p-4 md:p-8">
           <div className="max-w-7xl mx-auto">
               {/* Header */}
               <div className="flex justify-between items-center mb-8">
                   <h1 className="text-3xl font-bold text-gray-900">Admin Dashboard</h1>
                   <div className="flex gap-4">
                       <a 
                           href="/export-excel"
                           className="inline-flex items-center px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
                       >
                           Excel Export
                       </a>
                       <a 
                           href="/logout"
                           className="inline-flex items-center px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700"
                       >
                           Logout
                       </a>
                   </div>
               </div>

               {/* Stats Cards */}
               <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                   <div className="bg-white p-6 rounded-lg shadow">
                       <h3 className="text-lg font-semibold">Gesamt Anmeldungen</h3>
                       <p className="text-3xl font-bold mt-2">{stats.total_registrations}</p>
                   </div>
                   <div className="bg-white p-6 rounded-lg shadow">
                       <h3 className="text-lg font-semibold">Bestätigte Anmeldungen</h3>
                       <p className="text-3xl font-bold mt-2">{stats.confirmed_registrations}</p>
                   </div>
                   <div className="bg-white p-6 rounded-lg shadow">
                       <h3 className="text-lg font-semibold">Angemeldete Kinder</h3>
                       <p className="text-3xl font-bold mt-2">{stats.total_children}</p>
                   </div>
               </div>

               {/* Registrations Table */}
               <div className="bg-white rounded-lg shadow overflow-hidden">
                   <div className="overflow-x-auto">
                       <table className="w-full">
                           <thead className="bg-gray-50">
                               <tr>
                                   <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                       Zeitstempel
                                   </th>
                                   <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                       Kinder
                                   </th>
                                   <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                       Erziehungsberechtigte/r
                                   </th>
                                   <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                       Aktionen
                                   </th>
                               </tr>
                           </thead>
                           <tbody className="bg-white divide-y divide-gray-200">
                               {registrations.map((registration) => {
                                   const [showModal, setShowModal] = React.useState(false);
                                   const formRef = React.useRef();
                                   
                                   return (
                                       <tr key={registration.id} className={registration.confirmed ? 'bg-green-50' : ''}>
                                           <td className="px-6 py-4 whitespace-nowrap">
                                               {registration.created_at}
                                           </td>
                                           <td className="px-6 py-4">
                                               {registration.children.map((child, idx) => (
                                                   <div key={idx} className="mb-2">
                                                       <p className="font-medium">
                                                           {child.child_firstname} {child.child_lastname}
                                                       </p>
                                                       <p className="text-sm">Geb.: {child.birthdate}</p>
                                                       <p className="text-sm">
                                                           Allergien: {child.allergies || "-"}
                                                       </p>
                                                       <p className="text-sm">
                                                           Verein: {child.club_membership}
                                                       </p>
                                                   </div>
                                               ))}
                                           </td>
                                           <td className="px-6 py-4">
                                               <p>Name: {registration.parent_firstname} {registration.parent_lastname}</p>
                                               <p>Telefonnummer: {registration.phone_number}</p>
                                               <p>E-Mail: {registration.email}</p>
                                           </td>
                                           <td className="px-6 py-4">
                                               <div className="flex flex-col space-y-2">
                                                   <form action={`/confirm-mail/${registration.id}`} method="post">
                                                       <input type="hidden" name="csrf_token" value={csrfToken} />
                                                       <button
                                                           type="submit"
                                                           className={`w-full px-4 py-2 text-white rounded-md ${
                                                               registration.confirmed 
                                                               ? 'bg-gray-400 cursor-not-allowed' 
                                                               : 'bg-blue-600 hover:bg-blue-700'
                                                           }`}
                                                           disabled={registration.confirmed}
                                                       >
                                                           Bestätigen
                                                       </button>
                                                   </form>
                                                   <form ref={formRef} action={`/delete-entry/${registration.id}`} method="post">
                                                       <input type="hidden" name="csrf_token" value={csrfToken} />
                                                       <button
                                                           type="button"
                                                           onClick={() => setShowModal(true)}
                                                           className="w-full px-4 py-2 text-white bg-red-600 hover:bg-red-700 rounded-md"
                                                       >
                                                           Löschen
                                                       </button>
                                                       <DeleteConfirmModal 
                                                           isOpen={showModal}
                                                           onConfirm={() => {
                                                               formRef.current.submit();
                                                               setShowModal(false);
                                                           }}
                                                           onCancel={() => setShowModal(false)}
                                                       />
                                                   </form>
                                               </div>
                                           </td>
                                       </tr>
                                   );
                               })}
                           </tbody>
                       </table>
                   </div>
               </div>

               {/* Delete All Section */}
               <div className="mt-8">
                   {showDeleteConfirm ? (
                       <div className="bg-red-50 border border-red-200 rounded-md p-4">
                           <p className="text-red-800 mb-4">
                               Möchten Sie wirklich alle Einträge löschen? Diese Aktion kann nicht rückgängig gemacht werden.
                           </p>
                           <div className="flex space-x-4">
                               <form action="/delete-all-entries" method="post">
                                   <input type="hidden" name="csrf_token" value={csrfToken} />
                                   <button
                                       type="submit"
                                       className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700"
                                   >
                                       Ja, alle löschen
                                   </button>
                               </form>
                               <button
                                   onClick={() => setShowDeleteConfirm(false)}
                                   className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700"
                               >
                                   Abbrechen
                               </button>
                           </div>
                       </div>
                   ) : (
                       <button
                           onClick={() => setShowDeleteConfirm(true)}
                           className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700"
                       >
                           Alle Einträge löschen
                       </button>
                   )}
               </div>
           </div>
       </div>
   );
};

const rootElement = document.getElementById('root');
const root = ReactDOM.createRoot(rootElement);
root.render(<AdminDashboard />);