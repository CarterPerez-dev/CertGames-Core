// src/components/shared/ConfirmModal.js
import './ConfirmModal.css'; 

function showConfirmModal(message) {
  return new Promise((resolve, reject) => {


    const backdrop = document.createElement('div');
    backdrop.className = 'confirm-modal-backdrop';

    const modalContent = document.createElement('div');
    modalContent.className = 'confirm-modal-content';

    const messageElement = document.createElement('p');
    messageElement.className = 'confirm-modal-message';
    messageElement.textContent = message;

    const buttonContainer = document.createElement('div');
    buttonContainer.className = 'confirm-modal-buttons';

    const confirmButton = document.createElement('button');
    confirmButton.textContent = 'Confirm';
    confirmButton.className = 'confirm-modal-button confirm';

    const cancelButton = document.createElement('button');
    cancelButton.textContent = 'Cancel';
    cancelButton.className = 'confirm-modal-button cancel';


    buttonContainer.appendChild(cancelButton);
    buttonContainer.appendChild(confirmButton);
    modalContent.appendChild(messageElement);
    modalContent.appendChild(buttonContainer);
    backdrop.appendChild(modalContent);




    const cleanup = () => {

      if (backdrop.parentNode === document.body) {
        document.body.removeChild(backdrop);
      }
    };

    confirmButton.onclick = () => {
      cleanup();
      resolve(true); 
    };

    cancelButton.onclick = () => {
      cleanup();
      reject(new Error('User cancelled')); 

    };


    backdrop.onclick = (event) => {
      if (event.target === backdrop) {
        cleanup();
        reject(new Error('User cancelled by clicking backdrop'));
      }
    };


    document.body.appendChild(backdrop);

  }); 
} 

export default showConfirmModal;
