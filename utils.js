function checkText(searchText, selector) {
  // Récupérer la référence à la table
  var table = document.getElementById("myTable");

  // Récupérer toutes les lignes du tableau, sauf l'en-tête
  var rows = Array.from(table.getElementsByTagName("tr")).slice(1);

  // Parcourir les lignes et afficher/cacher en fonction du texte de recherche
  rows.forEach(function(row) {
    var cveCell = row.querySelector(selector);
    var cveText = cveCell.innerHTML.toLowerCase();
    if (cveText.includes(searchText)) {
      row.style.display = ""; // Afficher la ligne
    } else {
      row.style.display = "none"; // Cacher la ligne
    }
  });

  if(searchText==""){
    renderTable();
  }
}

