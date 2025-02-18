// craco.config.js
module.exports = {
  webpack: {
    configure: (webpackConfig) => {
      // Filter out the CssMinimizerPlugin from the list of minimizers
      webpackConfig.optimization.minimizer = webpackConfig.optimization.minimizer.filter(
        (plugin) => plugin.constructor.name !== 'CssMinimizerPlugin'
      );
      return webpackConfig;
    },
  },
};
